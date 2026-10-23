import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pymem
import pymem.process
import pymem.memory
import psutil
import struct
import time
import threading
import ctypes
import sys
import os

# ===== МУТЕКС =====
kernel32 = ctypes.windll.kernel32
MUTEX_NAME = "Global\\MemoryScannerUniqueMutex_v5"
mutex = kernel32.CreateMutexW(None, True, MUTEX_NAME)
if kernel32.GetLastError() == 183:
    sys.exit(0)


# ===== СТРУКТУРА MEMORY_BASIC_INFORMATION =====
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


# ===== ПРОВЕРКА АДМИНКИ =====
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def restart_as_admin():
    """Перезапуск с правами администратора"""
    try:
        script_path = os.path.abspath(__file__)

        if script_path.lower().endswith('.py'):
            python_exe = sys.executable
            params = f'"{script_path}"'
        else:
            python_exe = script_path
            params = ''

        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, params,
            os.path.dirname(script_path), 1
        )

        if result > 32:
            sys.exit(0)
        else:
            return False, f"ShellExecute вернул код: {result}"
    except Exception as e:
        return False, str(e)


# ===== ТИПЫ ДАННЫХ =====
# fmt_signed — для отображения знаковых значений
# fmt_unsigned — для чтения/записи
SCAN_TYPES = {
    'uint8': {
        'name': 'Целое 1 байт (0-255)',
        'fmt': '<B', 'fmt_signed': '<b', 'size': 1, 'py': 'int',
        'min': 0, 'max': 255
    },
    'int8': {
        'name': 'Целое 1 байт знаковое (-128 до 127)',
        'fmt': '<b', 'fmt_signed': '<b', 'size': 1, 'py': 'int',
        'min': -128, 'max': 127
    },
    'uint16': {
        'name': 'Целое 2 байта (0-65535)',
        'fmt': '<H', 'fmt_signed': '<h', 'size': 2, 'py': 'int',
        'min': 0, 'max': 65535
    },
    'int16': {
        'name': 'Целое 2 байта знаковое (-32768 до 32767)',
        'fmt': '<h', 'fmt_signed': '<h', 'size': 2, 'py': 'int',
        'min': -32768, 'max': 32767
    },
    'uint24': {
        'name': 'Целое 3 байта (0-16777215)',
        'fmt': None, 'fmt_signed': None, 'size': 3, 'py': 'int',
        'min': 0, 'max': 16777215
    },
    'uint32': {
        'name': 'Целое 4 байта (0-4294967295)',
        'fmt': '<I', 'fmt_signed': '<i', 'size': 4, 'py': 'int',
        'min': 0, 'max': 4294967295
    },
    'int32': {
        'name': 'Целое 4 байта знаковое (-2147483648 до 2147483647)',
        'fmt': '<i', 'fmt_signed': '<i', 'size': 4, 'py': 'int',
        'min': -2147483648, 'max': 2147483647
    },
    'uint64': {
        'name': 'Целое 8 байт',
        'fmt': '<Q', 'fmt_signed': '<q', 'size': 8, 'py': 'int',
        'min': 0, 'max': 18446744073709551615
    },
    'float32': {
        'name': 'Float 4 байта',
        'fmt': '<f', 'fmt_signed': '<f', 'size': 4, 'py': 'float',
        'min': -3.4e38, 'max': 3.4e38
    },
    'float64': {
        'name': 'Double 8 байт',
        'fmt': '<d', 'fmt_signed': '<d', 'size': 8, 'py': 'float',
        'min': -1.7e308, 'max': 1.7e308
    },
}


# ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====

def get_3byte(data, offset):
    """Чтение 3-байтного беззнакового целого (little-endian)"""
    if offset + 2 >= len(data):
        return None
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)


def pack_3byte(value):
    """Упаковка 3-байтного целого"""
    value = int(value) & 0xFFFFFF  # Обрезаем до 3 байт
    return struct.pack('<I', value)[:3]


def read_value(type_key, data, offset):
    """Безопасное чтение значения из байтов"""
    t = SCAN_TYPES[type_key]
    fmt = t['fmt']
    size = t['size']

    # Проверяем что данных достаточно
    if offset + size > len(data):
        return None

    try:
        if fmt is None and size == 3:
            return get_3byte(data, offset)
        elif fmt is not None:
            return struct.unpack_from(fmt, data, offset)[0]
        else:
            return None
    except Exception:
        return None


def value_to_bytes(type_key, value):
    """Безопасное преобразование значения в байты"""
    t = SCAN_TYPES[type_key]
    fmt = t['fmt']

    try:
        if t['size'] == 3:
            return pack_3byte(value)
        elif t['py'] == 'float':
            return struct.pack(fmt, float(value))
        else:
            # Для int типов — обрезаем до нужного диапазона
            int_val = int(value)
            # Маскируем по размеру
            if t['size'] == 1:
                int_val = int_val & 0xFF
            elif t['size'] == 2:
                int_val = int_val & 0xFFFF
            elif t['size'] == 4:
                int_val = int_val & 0xFFFFFFFF
            elif t['size'] == 8:
                int_val = int_val & 0xFFFFFFFFFFFFFFFF
            return struct.pack(fmt, int_val)
    except Exception as e:
        raise ValueError(f"Не удалось преобразовать '{value}' в тип {t['name']}: {e}")


def parse_search_value(type_key, search_value):
    """Парсинг поискового значения с проверкой типа"""
    t = SCAN_TYPES[type_key]

    try:
        if t['py'] == 'float':
            val = float(search_value)
            if val < t['min'] or val > t['max']:
                return None, f"Значение {val} вне диапазона [{t['min']}, {t['max']}]"
            return val, None
        else:
            val = int(search_value)
            if val < t['min'] or val > t['max']:
                return None, f"Значение {val} вне диапазона [{t['min']}, {t['max']}]"
            return val, None
    except ValueError:
        return None, f"'{search_value}' не является числом для типа {t['name']}"


def get_processes(filter_text=''):
    """Получить список процессов"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and name.lower().endswith('.exe'):
                processes.append((proc.info['pid'], name))
        except:
            pass

    seen = set()
    unique = []
    for pid, name in sorted(processes, key=lambda x: x[1]):
        if name.lower() not in seen:
            seen.add(name.lower())
            unique.append((pid, name))

    if filter_text:
        filter_lower = filter_text.lower()
        unique = [(pid, name) for pid, name in unique if filter_lower in name.lower()]

    return unique


def get_memory_regions(handle):
    """Получить все регионы памяти процесса через VirtualQueryEx"""
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    mbi_size = ctypes.sizeof(mbi)

    max_iterations = 500000
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        result = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            mbi_size
        )

        if result == 0:
            break

        base_addr = mbi.BaseAddress

        # Защита от None и 0
        if base_addr is None or base_addr == 0:
            address += 0x10000
            continue

        region_size = mbi.RegionSize
        if region_size == 0:
            region_size = 0x1000

        regions.append({
            'BaseAddress': base_addr,
            'RegionSize': region_size,
            'State': mbi.State,
            'Protect': mbi.Protect,
        })

        next_addr = base_addr + region_size

        if next_addr <= base_addr or next_addr > 0x7FFFFFFFFFFF:
            break

        address = next_addr

    return regions


class MemoryScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Scanner v1.0 — Аналог ArtMoney")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        self.root.resizable(True, True)

        self.pm = None
        self.process_name = None
        self.process_pid = None
        self.selected_types = set(SCAN_TYPES.keys())
        self.scan_results = {}
        self.scan_history = {}
        self.is_scanning = False
        self.freeze_threads = {}
        self.process_panel_visible = False

        self.admin_ok = is_admin()

        if not self.admin_ok:
            self.build_no_admin_ui()
        else:
            self.build_ui()

    def build_no_admin_ui(self):
        self.root.geometry("550x400")
        self.root.resizable(False, False)

        main_frame = ttk.Frame(self.root, padding=30)
        main_frame.pack(fill='both', expand=True)

        ttk.Label(main_frame, text="⚠️ Требуются права администратора",
                  font=('Arial', 16, 'bold'), foreground='red').pack(pady=20)

        ttk.Label(main_frame,
                  text="Для работы с памятью процессов\nнеобходимы права администратора.",
                  font=('Arial', 12), justify='center').pack(pady=15)

        ttk.Label(main_frame, text="🔑 Админ:  Выключена",
                  font=('Arial', 13, 'bold'), foreground='red').pack(pady=15)

        ttk.Button(main_frame, text="🚀 Запустить от имени администратора",
                   command=self.on_run_as_admin).pack(pady=20, ipadx=30, ipady=12)

        ttk.Button(main_frame, text="️ Продолжить без прав (ограниченный функционал)",
                   command=self.on_continue_without_admin).pack(pady=5)

        ttk.Label(main_frame, text="⚠️ Без админки многие процессы будут недоступны!",
                  font=('Arial', 9), foreground='orange').pack(pady=10)

        self.status_msg = ttk.Label(main_frame, text="", font=('Arial', 9), foreground='gray')
        self.status_msg.pack(pady=5)

    def on_run_as_admin(self):
        self.status_msg.config(text="⏳ Запуск с правами администратора...", foreground='blue')
        self.root.update()

        success, error = restart_as_admin()

        if not success:
            self.status_msg.config(text=f"❌ Ошибка: {error}", foreground='red')
            messagebox.showerror("Ошибка запуска",
                                 f"Не удалось запустить с правами администратора:\n\n{error}\n\n"
                                 f"Попробуй:\n"
                                 f"1. Правый клик на файл → 'Запуск от имени администратора'\n"
                                 f"2. Или запусти PyCharm/терминал от админа")

    def on_continue_without_admin(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.admin_ok = False
        self.build_ui()

    def update_admin_status(self):
        if self.admin_ok:
            self.admin_label.config(text="🔑 Админ: ✅ Включена", foreground='green')
        else:
            self.admin_label.config(text="⚠️ Админ: ❌ Выключена (ограничено)", foreground='orange')

    def build_ui(self):
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill='x', padx=5, pady=5)

        self.proc_btn = ttk.Button(top_frame, text="📋 Процессы", command=self.toggle_process_panel)
        self.proc_btn.pack(side='left', padx=2)

        self.proc_status_label = ttk.Label(top_frame, text="Процесс не выбран", foreground='red')
        self.proc_status_label.pack(side='left', padx=10)

        self.admin_label = ttk.Label(top_frame, text="", font=('Arial', 10, 'bold'))
        self.admin_label.pack(side='right', padx=10)

        self.update_admin_status()

        # Панель процессов
        self.proc_panel = ttk.Frame(self.root, relief='groove', borderwidth=2)

        proc_search_frame = ttk.Frame(self.proc_panel)
        proc_search_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(proc_search_frame, text=" Поиск:").pack(side='left', padx=5)
        self.proc_search_var = tk.StringVar()
        self.proc_search_var.trace_add('write', lambda *args: self.filter_processes())
        self.proc_search_entry = ttk.Entry(proc_search_frame, textvariable=self.proc_search_var, width=30)
        self.proc_search_entry.pack(side='left', padx=5, fill='x', expand=True)

        ttk.Button(proc_search_frame, text="🔄 Обновить", command=self.refresh_processes).pack(side='right', padx=5)

        proc_list_frame = ttk.Frame(self.proc_panel)
        proc_list_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.proc_listbox = tk.Listbox(proc_list_frame, height=12, selectmode='browse', font=('Consolas', 10))
        self.proc_listbox.pack(side='left', fill='both', expand=True)
        self.proc_listbox.bind('<Double-1>', lambda e: self.on_process_select())
        self.proc_listbox.bind('<Return>', lambda e: self.on_process_select())

        proc_scroll = ttk.Scrollbar(proc_list_frame, orient='vertical', command=self.proc_listbox.yview)
        proc_scroll.pack(side='right', fill='y')
        self.proc_listbox.config(yscrollcommand=proc_scroll.set)

        proc_btn_frame = ttk.Frame(self.proc_panel)
        proc_btn_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(proc_btn_frame, text="✅ Выбрать", command=self.on_process_select).pack(side='left', padx=5)
        ttk.Button(proc_btn_frame, text="❌ Закрыть", command=self.toggle_process_panel).pack(side='right', padx=5)

        self.proc_count_label = ttk.Label(proc_btn_frame, text="")
        self.proc_count_label.pack(side='right', padx=10)

        self.refresh_processes()

        # Параметры поиска
        search_frame = ttk.LabelFrame(self.root, text="Параметры поиска", padding=5)
        search_frame.pack(fill='x', padx=5, pady=5)

        types_frame = ttk.LabelFrame(search_frame, text="Типы данных (можно несколько)", padding=3)
        types_frame.pack(fill='x', pady=3)

        self.type_vars = {}
        type_check_frame = ttk.Frame(types_frame)
        type_check_frame.pack(fill='x')

        col = 0
        row = 0
        for key, info in SCAN_TYPES.items():
            var = tk.BooleanVar(value=True)
            self.type_vars[key] = var
            cb = ttk.Checkbutton(type_check_frame, text=info['name'], variable=var,
                                 command=self.update_selected_types)
            cb.grid(row=row, column=col, sticky='w', padx=8, pady=3)
            col += 1
            if col >= 3:
                col = 0
                row += 1

        value_frame = ttk.Frame(search_frame)
        value_frame.pack(fill='x', pady=5)

        ttk.Label(value_frame, text="Значение:").pack(side='left', padx=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(value_frame, textvariable=self.search_var, width=25)
        self.search_entry.pack(side='left', padx=5)
        self.search_entry.bind('<Return>', lambda e: self.first_scan_exact())

        first_scan_frame = ttk.Frame(search_frame)
        first_scan_frame.pack(fill='x', pady=5)

        self.btn_first_exact = ttk.Button(first_scan_frame, text="🔍 Первый поиск (точное значение)",
                                          command=self.first_scan_exact)
        self.btn_first_exact.pack(side='left', padx=2)

        self.btn_first_unknown = ttk.Button(first_scan_frame, text="🔎 Первый поиск (неизвестное значение)",
                                            command=self.first_scan_unknown)
        self.btn_first_unknown.pack(side='left', padx=2)

        filter_frame = ttk.Frame(search_frame)
        filter_frame.pack(fill='x', pady=5)

        self.btn_next = ttk.Button(filter_frame, text="🎯 Точное значение", command=self.next_scan_exact)
        self.btn_next.pack(side='left', padx=2)

        self.btn_changed = ttk.Button(filter_frame, text="📈 Изменилось", command=self.filter_changed)
        self.btn_changed.pack(side='left', padx=2)

        self.btn_unchanged = ttk.Button(filter_frame, text="📊 Не изменилось", command=self.filter_unchanged)
        self.btn_unchanged.pack(side='left', padx=2)

        self.btn_reset = ttk.Button(filter_frame, text=" Сбросить", command=self.reset_results)
        self.btn_reset.pack(side='left', padx=2)

        self.scan_status = ttk.Label(filter_frame, text="Готов к поиску", foreground='green')
        self.scan_status.pack(side='right', padx=5)

        # Результаты
        bottom_frame = ttk.LabelFrame(self.root, text="Результаты", padding=5)
        bottom_frame.pack(fill='both', expand=True, padx=5, pady=5)

        columns = ('addr', 'type', 'value', 'hex', 'frozen')
        self.tree = ttk.Treeview(bottom_frame, columns=columns, show='headings', selectmode='extended')

        self.tree.heading('addr', text='Адрес', command=lambda: self.sort_tree('addr'))
        self.tree.heading('type', text='Тип', command=lambda: self.sort_tree('type'))
        self.tree.heading('value', text='Значение', command=lambda: self.sort_tree('value'))
        self.tree.heading('hex', text='Hex', command=lambda: self.sort_tree('hex'))
        self.tree.heading('frozen', text='Замор.', command=lambda: self.sort_tree('frozen'))

        self.tree.column('addr', width=150, anchor='w')
        self.tree.column('type', width=160, anchor='w')
        self.tree.column('value', width=150, anchor='w')
        self.tree.column('hex', width=150, anchor='w')
        self.tree.column('frozen', width=70, anchor='center')

        tree_scroll_y = ttk.Scrollbar(bottom_frame, orient='vertical', command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(bottom_frame, orient='horizontal', command=self.tree.xview)
        self.tree.config(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        self.tree.pack(side='top', fill='both', expand=True)
        tree_scroll_y.pack(side='right', fill='y')
        tree_scroll_x.pack(side='bottom', fill='x')

        result_btn_frame = ttk.Frame(bottom_frame)
        result_btn_frame.pack(fill='x', pady=5)

        ttk.Button(result_btn_frame, text="️ Записать", command=self.write_selected).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text="❄️ Заморозить", command=self.freeze_selected).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text="🔓 Разморозить", command=self.unfreeze_selected).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text=" Разморозить все", command=self.unfreeze_all).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text="📋 Копировать адрес", command=self.copy_address).pack(side='left', padx=2)

        self.result_count = ttk.Label(result_btn_frame, text="Адресов: 0")
        self.result_count.pack(side='right', padx=5)

        addr_frame = ttk.Frame(bottom_frame)
        addr_frame.pack(fill='x', pady=3)

        ttk.Label(addr_frame, text="Адрес (hex):").pack(side='left', padx=5)
        self.addr_var = tk.StringVar()
        ttk.Entry(addr_frame, textvariable=self.addr_var, width=20).pack(side='left', padx=5)
        ttk.Button(addr_frame, text="📖 Прочитать", command=self.read_by_addr).pack(side='left', padx=2)
        ttk.Button(addr_frame, text="✏️ Записать", command=self.write_by_addr).pack(side='left', padx=2)

        self.addr_result = ttk.Label(addr_frame, text="")
        self.addr_result.pack(side='right', padx=5)

    def toggle_process_panel(self):
        if self.process_panel_visible:
            self.proc_panel.pack_forget()
            self.proc_btn.config(text="📋 Процессы")
            self.process_panel_visible = False
        else:
            self.proc_panel.pack(fill='x', padx=5, pady=2)
            self.proc_btn.config(text=" Скрыть процессы")
            self.process_panel_visible = True
            self.proc_search_entry.focus_set()

    def filter_processes(self):
        filter_text = self.proc_search_var.get()
        self.refresh_processes(filter_text)

    def refresh_processes(self, filter_text=''):
        self.proc_listbox.delete(0, 'end')
        processes = get_processes(filter_text)
        for pid, name in processes:
            self.proc_listbox.insert('end', f"{name}  (PID: {pid})")
        self.proc_count_label.config(text=f"Найдено: {len(processes)}")

    def on_process_select(self):
        selection = self.proc_listbox.curselection()
        if not selection:
            messagebox.showwarning("Внимание", "Выбери процесс из списка!")
            return

        idx = selection[0]
        filter_text = self.proc_search_var.get()
        processes = get_processes(filter_text)
        if idx >= len(processes):
            return

        pid, name = processes[idx]

        try:
            self.pm = pymem.Pymem()
            self.pm.open_process_from_id(pid)
            self.pm.process_id = pid
            self.process_name = name
            self.process_pid = pid
            self.proc_status_label.config(text=f"✅ {name} (PID: {pid})", foreground='green')

            if self.process_panel_visible:
                self.toggle_process_panel()

        except Exception as e:
            error_msg = str(e)
            if "Could not open process" in error_msg or "access" in error_msg.lower():
                msg = (f"❌ Не удалось подключиться к {name} (PID: {pid})\n\n"
                       f"Ошибка: {error_msg}\n\n"
                       f"Возможные причины:\n"
                       f"• Программа запущена без прав администратора\n"
                       f"• Процесс защищён античитом\n"
                       f"• Процесс уже закрылся")
                messagebox.showerror("Ошибка подключения", msg)
            else:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к {name}:\n{error_msg}")

    def update_selected_types(self):
        self.selected_types = {k for k, v in self.type_vars.items() if v.get()}

    def first_scan_exact(self):
        if self.pm is None:
            messagebox.showwarning("Внимание", "Сначала выбери процесс!")
            return

        if not self.selected_types:
            messagebox.showwarning("Внимание", "Выбери хотя бы один тип данных!")
            return

        search_value = self.search_var.get().strip()
        if not search_value:
            messagebox.showwarning("Внимание", "Введи значение для поиска!")
            return

        # Проверяем что значение валидно для хотя бы одного типа
        valid_for_any = False
        for type_key in self.selected_types:
            val, err = parse_search_value(type_key, search_value)
            if err is None:
                valid_for_any = True
                break

        if not valid_for_any:
            messagebox.showwarning("Внимание",
                                   f"Значение '{search_value}' не подходит ни для одного выбранного типа данных!\n\n"
                                   f"Проверь что ввёл число (например: 850000 или 15.5)")
            return

        self.is_scanning = True
        self.scan_status.config(text="🔍 Сканирование...", foreground='orange')
        self.btn_first_exact.config(state='disabled')
        self.btn_first_unknown.config(state='disabled')

        thread = threading.Thread(target=self._do_first_scan, args=(search_value, False), daemon=True)
        thread.start()

    def first_scan_unknown(self):
        if self.pm is None:
            messagebox.showwarning("Внимание", "Сначала выбери процесс!")
            return

        if not self.selected_types:
            messagebox.showwarning("Внимание", "Выбери хотя бы один тип данных!")
            return

        self.is_scanning = True
        self.scan_status.config(text="🔎 Сканирование неизвестных...", foreground='orange')
        self.btn_first_exact.config(state='disabled')
        self.btn_first_unknown.config(state='disabled')

        thread = threading.Thread(target=self._do_first_scan, args=('', True), daemon=True)
        thread.start()

    def _do_first_scan(self, search_value, is_unknown):
        try:
            start_time = time.time()
            new_results = {}
            new_history = {}
            regions_checked = 0
            total_entries = 0
            errors = []

            regions = get_memory_regions(self.pm.process_handle)

            for type_key in self.selected_types:
                if not self.is_scanning:
                    break

                t = SCAN_TYPES[type_key]
                target_size = t['size']

                if is_unknown:
                    target_bytes = None
                    parsed_value = None
                else:
                    parsed_value, err = parse_search_value(type_key, search_value)
                    if err is not None:
                        errors.append(f"{t['name']}: {err}")
                        continue
                    try:
                        target_bytes = value_to_bytes(type_key, parsed_value)
                    except ValueError as e:
                        errors.append(f"{t['name']}: {e}")
                        continue

                for region in regions:
                    if not self.is_scanning:
                        break

                    base_addr = region['BaseAddress']
                    if base_addr is None or base_addr == 0:
                        continue

                    if region['State'] != 0x1000:  # MEM_COMMIT
                        continue

                    if region['Protect'] not in (0x04, 0x40, 0x02):
                        continue

                    region_size = region['RegionSize']
                    if region_size < target_size:
                        continue

                    max_read = min(region_size, 64 * 1024 * 1024)

                    try:
                        data = self.pm.read_bytes(base_addr, max_read)
                    except:
                        continue

                    if len(data) < target_size:
                        continue

                    regions_checked += 1

                    if is_unknown:
                        pos = 0
                        while pos <= len(data) - target_size:
                            addr = base_addr + pos
                            val = read_value(type_key, data, pos)
                            if val is not None:
                                if addr not in new_results:
                                    new_results[addr] = {}
                                new_results[addr][type_key] = val
                                if addr not in new_history:
                                    new_history[addr] = {}
                                new_history[addr][type_key] = val
                                total_entries += 1
                            pos += 1
                    else:
                        pos = 0
                        while pos <= len(data) - target_size:
                            if data[pos:pos + target_size] == target_bytes:
                                addr = base_addr + pos
                                val = read_value(type_key, data, pos)
                                if val is not None:
                                    if addr not in new_results:
                                        new_results[addr] = {}
                                    new_results[addr][type_key] = val
                                    if addr not in new_history:
                                        new_history[addr] = {}
                                    new_history[addr][type_key] = val
                                    total_entries += 1
                                pos += target_size
                            else:
                                pos += 1

            self.scan_results = new_results
            self.scan_history = new_history

            elapsed = time.time() - start_time

            error_msg = ""
            if errors:
                error_msg = f"\n⚠️ Пропущено типов: {len(errors)}"

            self.root.after(0, self._scan_complete, total_entries, elapsed, regions_checked, error_msg)

        except Exception as e:
            self.root.after(0, self._scan_error, str(e))

    def _scan_complete(self, count, elapsed, regions, extra_msg=''):
        self.is_scanning = False
        self.btn_first_exact.config(state='normal')
        self.btn_first_unknown.config(state='normal')
        self.scan_status.config(
            text=f"✅ Найдено: {count} записей за {elapsed:.1f}с ({regions} регионов){extra_msg}",
            foreground='green'
        )
        self.refresh_tree()

    def _scan_error(self, error):
        self.is_scanning = False
        self.btn_first_exact.config(state='normal')
        self.btn_first_unknown.config(state='normal')
        self.scan_status.config(text=" Ошибка!", foreground='red')
        messagebox.showerror("Ошибка сканирования", error)

    def next_scan_exact(self):
        if not self.scan_results:
            messagebox.showwarning("Внимание", "Сначала сделай первый поиск!")
            return

        search_value = self.search_var.get().strip()
        if not search_value:
            messagebox.showwarning("Внимание", "Введи значение!")
            return

        new_results = {}

        for addr, types in self.scan_results.items():
            for type_key, old_val in list(types.items()):
                t = SCAN_TYPES[type_key]

                parsed_value, err = parse_search_value(type_key, search_value)
                if err is not None:
                    continue

                try:
                    target_bytes = value_to_bytes(type_key, parsed_value)
                    data = self.pm.read_bytes(addr, t['size'])

                    if data == target_bytes:
                        val = read_value(type_key, data, 0)
                        if val is not None:
                            if addr not in new_results:
                                new_results[addr] = {}
                            new_results[addr][type_key] = val
                except:
                    pass

        self.scan_results = new_results
        self.refresh_tree()
        total = sum(len(t) for t in new_results.values())
        self.scan_status.config(text=f"✅ Осталось: {total} записей", foreground='green')

    def filter_changed(self):
        if not self.scan_results:
            messagebox.showwarning("Внимание", "Сначала сделай первый поиск!")
            return

        new_results = {}
        changed = 0
        unchanged = 0

        for addr, types in self.scan_results.items():
            for type_key, old_val in list(types.items()):
                t = SCAN_TYPES[type_key]
                try:
                    data = self.pm.read_bytes(addr, t['size'])
                    current_val = read_value(type_key, data, 0)

                    if current_val is not None and old_val is not None and current_val != old_val:
                        if addr not in new_results:
                            new_results[addr] = {}
                        new_results[addr][type_key] = current_val
                        changed += 1
                    else:
                        unchanged += 1
                except:
                    pass

        self.scan_results = new_results
        self.refresh_tree()
        self.scan_status.config(text=f"✅ Изменилось: {changed}, Не изменилось: {unchanged}", foreground='green')

    def filter_unchanged(self):
        if not self.scan_results:
            messagebox.showwarning("Внимание", "Сначала сделай первый поиск!")
            return

        new_results = {}

        for addr, types in self.scan_results.items():
            for type_key, old_val in list(types.items()):
                t = SCAN_TYPES[type_key]
                try:
                    data = self.pm.read_bytes(addr, t['size'])
                    current_val = read_value(type_key, data, 0)

                    if current_val is not None and old_val is not None and current_val == old_val:
                        if addr not in new_results:
                            new_results[addr] = {}
                        new_results[addr][type_key] = current_val
                except:
                    pass

        self.scan_results = new_results
        self.refresh_tree()
        total = sum(len(t) for t in new_results.values())
        self.scan_status.config(text=f"✅ Неизменившихся: {total}", foreground='green')

    def reset_results(self):
        self.scan_results = {}
        self.scan_history = {}
        self.refresh_tree()
        self.scan_status.config(text="🗑 Сброшено", foreground='blue')

    def sort_tree(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            items.sort(key=lambda x: float(x[0]) if x[0].replace('.', '', 1).replace('-', '', 1).isdigit() else x[0])
        except:
            items.sort()
        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

    def format_value(self, type_key, val):
        """Форматирование значения для отображения"""
        if val is None:
            return "N/A"
        t = SCAN_TYPES[type_key]
        if t['py'] == 'float':
            return f"{val:.6f}"
        else:
            return str(val)

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())

        total = 0
        for addr in sorted(self.scan_results.keys()):
            types = self.scan_results[addr]
            for type_key in sorted(types.keys()):
                val = types[type_key]
                t = SCAN_TYPES[type_key]

                val_str = self.format_value(type_key, val)

                try:
                    raw = self.pm.read_bytes(addr, t['size'])
                    hex_str = raw.hex()
                except:
                    hex_str = "???"

                frozen = "❄️" if addr in self.freeze_threads and type_key in self.freeze_threads[addr] else ""

                self.tree.insert('', 'end', values=(f"0x{addr:X}", t['name'], val_str, hex_str, frozen))
                total += 1

        self.result_count.config(text=f"Адресов: {len(self.scan_results)}, Записей: {total}")

    def write_selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выбери строку в таблице!")
            return

        item = self.tree.item(selection[0])
        addr_str, type_name, old_val, _, _ = item['values']
        addr = int(addr_str, 16)

        type_key = None
        for k, v in SCAN_TYPES.items():
            if v['name'] == type_name:
                type_key = k
                break

        if type_key is None:
            return

        t = SCAN_TYPES[type_key]
        hint = f"диапазон: {t['min']} до {t['max']}" if t['py'] == 'int' else "например: 15.5"

        new_val = simpledialog.askstring("Запись значения",
                                         f"Новое значение для 0x{addr:X} ({type_name}):\nТекущее: {old_val}\n({hint})")
        if new_val is None:
            return

        # Валидация
        parsed, err = parse_search_value(type_key, new_val)
        if err:
            messagebox.showerror("Ошибка", err)
            return

        try:
            bytes_data = value_to_bytes(type_key, parsed)
            self.pm.write_bytes(addr, bytes_data, len(bytes_data))

            if addr in self.scan_results and type_key in self.scan_results[addr]:
                self.scan_results[addr][type_key] = parsed

            self.refresh_tree()
            messagebox.showinfo("Успех", f"Записано {new_val} по адресу 0x{addr:X}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def freeze_selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выбери строку!")
            return

        item = self.tree.item(selection[0])
        addr_str, type_name, old_val, _, _ = item['values']
        addr = int(addr_str, 16)

        type_key = None
        for k, v in SCAN_TYPES.items():
            if v['name'] == type_name:
                type_key = k
                break

        if type_key is None:
            return

        freeze_val = simpledialog.askstring("Заморозка",
                                            f"Значение для заморозки 0x{addr:X}:\n(оставь пустым для текущего: {old_val})")
        if freeze_val is None:
            return
        if not freeze_val:
            freeze_val = old_val

        # Валидация
        parsed, err = parse_search_value(type_key, freeze_val)
        if err:
            messagebox.showerror("Ошибка", err)
            return

        if addr in self.freeze_threads and type_key in self.freeze_threads[addr]:
            self.freeze_threads[addr][type_key][1].set()
            del self.freeze_threads[addr][type_key]

        try:
            bytes_data = value_to_bytes(type_key, parsed)
            stop_event = threading.Event()

            def worker():
                while not stop_event.is_set():
                    try:
                        self.pm.write_bytes(addr, bytes_data, len(bytes_data))
                    except:
                        pass
                    time.sleep(0.1)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()

            if addr not in self.freeze_threads:
                self.freeze_threads[addr] = {}
            self.freeze_threads[addr][type_key] = (thread, stop_event)

            self.refresh_tree()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def unfreeze_selected(self):
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        addr_str, type_name, _, _, _ = item['values']
        addr = int(addr_str, 16)

        type_key = None
        for k, v in SCAN_TYPES.items():
            if v['name'] == type_name:
                type_key = k
                break

        if type_key and addr in self.freeze_threads and type_key in self.freeze_threads[addr]:
            self.freeze_threads[addr][type_key][1].set()
            del self.freeze_threads[addr][type_key]
            if not self.freeze_threads[addr]:
                del self.freeze_threads[addr]
            self.refresh_tree()

    def unfreeze_all(self):
        for addr, types in self.freeze_threads.items():
            for type_key, (thread, event) in types.items():
                event.set()
        self.freeze_threads.clear()
        self.refresh_tree()

    def copy_address(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        addr_str = item['values'][0]
        self.root.clipboard_clear()
        self.root.clipboard_append(addr_str)

    def read_by_addr(self):
        addr_str = self.addr_var.get().strip()
        if not addr_str:
            return

        try:
            addr = int(addr_str, 16)
        except:
            try:
                addr = int(addr_str)
            except:
                self.addr_result.config(text="❌ Неверный адрес!", foreground='red')
                return

        try:
            data = self.pm.read_bytes(addr, 8)

            result = f"Hex: {data[:4].hex()}"
            if len(data) >= 4:
                result += f" | Int32: {struct.unpack('<i', data[:4])[0]}"
                result += f" | UInt32: {struct.unpack('<I', data[:4])[0]}"
                result += f" | Float: {struct.unpack('<f', data[:4])[0]:.6f}"
            if len(data) >= 2:
                result += f" | Int16: {struct.unpack('<h', data[:2])[0]}"

            self.addr_result.config(text=result[:100], foreground='green')
        except Exception as e:
            self.addr_result.config(text=f"❌ Ошибка: {e}", foreground='red')

    def write_by_addr(self):
        addr_str = self.addr_var.get().strip()
        if not addr_str:
            return

        try:
            addr = int(addr_str, 16)
        except:
            try:
                addr = int(addr_str)
            except:
                self.addr_result.config(text="❌ Неверный адрес!", foreground='red')
                return

        value = simpledialog.askstring("Запись", f"Значение для 0x{addr:X}:")
        if value is None:
            return

        try:
            bytes_data = struct.pack('<I', int(value) & 0xFFFFFFFF)
            self.pm.write_bytes(addr, bytes_data, 4)
            self.addr_result.config(text=f"✅ Записано {value}", foreground='green')
        except Exception as e:
            self.addr_result.config(text=f"❌ Ошибка: {e}", foreground='red')


if __name__ == '__main__':
    root = tk.Tk()
    app = MemoryScannerApp(root)
    root.mainloop()
