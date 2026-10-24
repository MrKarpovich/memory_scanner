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
import copy
import asyncio
import logging
import queue
from datetime import datetime
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardRemove
from aiogram.filters import Command
from aiogram.exceptions import TelegramRetryAfter, TelegramForbiddenError, TelegramBadRequest
from aiogram.fsm.storage.memory import MemoryStorage

# Загружаем переменные окружения
load_dotenv()

# ===== НАСТРОЙКА ЛОГИРОВАНИЯ =====
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

# ===== МУТЕКС =====
kernel32 = ctypes.windll.kernel32
MUTEX_NAME = "Global\\MemoryScannerUniqueMutex_v14"
mutex = kernel32.CreateMutexW(None, True, MUTEX_NAME)
if kernel32.GetLastError() == 183:
    sys.exit(0)


# ===== СТРУКТУРА MEMORY_BASIC_INFORMATION =====
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong), ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong),
    ]


# ===== ПРОВЕРКА АДМИНКИ =====
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def restart_as_admin():
    try:
        script_path = os.path.abspath(__file__)
        python_exe = sys.executable if script_path.lower().endswith('.py') else script_path
        params = f'"{script_path}"' if script_path.lower().endswith('.py') else ''
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params, os.path.dirname(script_path), 1)
        if result > 32:
            sys.exit(0)
        return False, f"ShellExecute вернул код: {result}"
    except Exception as e:
        return False, str(e)


# ===== ТИПЫ ДАННЫХ =====
SCAN_TYPES = {
    'uint8': {'name': 'Целое 1 байт (0-255)', 'fmt': '<B', 'size': 1, 'py': 'int', 'min': 0, 'max': 255},
    'int8': {'name': 'Целое 1 байт знаковое (-128..127)', 'fmt': '<b', 'size': 1, 'py': 'int', 'min': -128, 'max': 127},
    'uint16': {'name': 'Целое 2 байта (0-65535)', 'fmt': '<H', 'size': 2, 'py': 'int', 'min': 0, 'max': 65535},
    'int16': {'name': 'Целое 2 байта знаковое', 'fmt': '<h', 'size': 2, 'py': 'int', 'min': -32768, 'max': 32767},
    'uint24': {'name': 'Целое 3 байта (0-16777215)', 'fmt': None, 'size': 3, 'py': 'int', 'min': 0, 'max': 16777215},
    'uint32': {'name': 'Целое 4 байта (0-4294967295)', 'fmt': '<I', 'size': 4, 'py': 'int', 'min': 0,
               'max': 4294967295},
    'int32': {'name': 'Целое 4 байта знаковое', 'fmt': '<i', 'size': 4, 'py': 'int', 'min': -2147483648,
              'max': 2147483647},
    'uint64': {'name': 'Целое 8 байт', 'fmt': '<Q', 'size': 8, 'py': 'int', 'min': 0, 'max': 18446744073709551615},
    'float32': {'name': 'Float 4 байта', 'fmt': '<f', 'size': 4, 'py': 'float', 'min': -3.4e38, 'max': 3.4e38},
    'float64': {'name': 'Double 8 байт', 'fmt': '<d', 'size': 8, 'py': 'float', 'min': -1.7e308, 'max': 1.7e308},
}


# ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
def get_3byte(data, offset):
    if offset + 2 >= len(data):
        return None
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)


def pack_3byte(value):
    return struct.pack('<I', int(value) & 0xFFFFFF)[:3]


def read_value(type_key, data, offset):
    t = SCAN_TYPES[type_key]
    if offset + t['size'] > len(data):
        return None
    try:
        if t['fmt'] is None and t['size'] == 3:
            return get_3byte(data, offset)
        elif t['fmt'] is not None:
            return struct.unpack_from(t['fmt'], data, offset)[0]
        return None
    except:
        return None


def value_to_bytes(type_key, value):
    t = SCAN_TYPES[type_key]
    try:
        if t['size'] == 3:
            return pack_3byte(value)
        elif t['py'] == 'float':
            return struct.pack(t['fmt'], float(value))
        else:
            int_val = int(value)
            if t['size'] == 1:
                int_val &= 0xFF
            elif t['size'] == 2:
                int_val &= 0xFFFF
            elif t['size'] == 4:
                int_val &= 0xFFFFFFFF
            elif t['size'] == 8:
                int_val &= 0xFFFFFFFFFFFFFFFF
            return struct.pack(t['fmt'], int_val)
    except Exception as e:
        raise ValueError(f"Ошибка преобразования: {e}")


def parse_search_value(type_key, search_value):
    t = SCAN_TYPES[type_key]
    try:
        val = float(search_value) if t['py'] == 'float' else int(search_value)
        if val < t['min'] or val > t['max']:
            return None, f"Вне диапазона [{t['min']}, {t['max']}]"
        return val, None
    except ValueError:
        return None, f"Не является числом для типа {t['name']}"


def get_processes(filter_text=''):
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and name.lower().endswith('.exe'):
                processes.append((proc.info['pid'], name))
        except:
            pass
    seen = set()
    unique = [(pid, name) for pid, name in sorted(processes, key=lambda x: x[1]) if
              not (name.lower() in seen or seen.add(name.lower()))]
    if filter_text:
        unique = [(pid, name) for pid, name in unique if filter_text.lower() in name.lower()]
    return unique


def get_memory_regions(handle):
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    mbi_size = ctypes.sizeof(mbi)
    for _ in range(500000):
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
        if result == 0:
            break
        base_addr = mbi.BaseAddress
        if base_addr is None or base_addr == 0:
            address += 0x10000
            continue
        region_size = mbi.RegionSize or 0x1000
        regions.append(
            {'BaseAddress': base_addr, 'RegionSize': region_size, 'State': mbi.State, 'Protect': mbi.Protect})
        next_addr = base_addr + region_size
        if next_addr <= base_addr or next_addr > 0x7FFFFFFFFFFF:
            break
        address = next_addr
    return regions


# ===== МЕНЕДЖЕР ДАННЫХ =====
class ScannerDataManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.pm = None
        self.process_name = None
        self.process_pid = None
        self.selected_types = set(SCAN_TYPES.keys())
        self.scan_results = {}
        self.scan_history = {}
        self.is_scanning = False
        self.freeze_threads = {}
        self.changed_addrs = set()
        self.history = []
        self.history_index = -1
        self.max_history = 50

        self.gui_update_queue = queue.Queue()
        self.bot_progress_queue = queue.Queue()

    def push_history(self, description):
        with self.lock:
            if self.history_index < len(self.history) - 1:
                self.history = self.history[:self.history_index + 1]
            self.history.append((copy.deepcopy(self.scan_results), copy.deepcopy(self.scan_history), description))
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]
            self.history_index = len(self.history) - 1

    def go_back(self):
        with self.lock:
            if self.history_index > 0:
                self.history_index -= 1
                self.scan_results = copy.deepcopy(self.history[self.history_index][0])
                self.scan_history = copy.deepcopy(self.history[self.history_index][1])
                self.changed_addrs.clear()
                return self.history[self.history_index][2]
        return None

    def go_forward(self):
        with self.lock:
            if self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.scan_results = copy.deepcopy(self.history[self.history_index][0])
                self.scan_history = copy.deepcopy(self.history[self.history_index][1])
                self.changed_addrs.clear()
                return self.history[self.history_index][2]
        return None

    def get_status(self):
        with self.lock:
            return {
                'process': self.process_name or "Не выбран",
                'types': len(self.selected_types),
                'results': sum(len(t) for t in self.scan_results.values()),
                'history': f"{self.history_index + 1}/{len(self.history)}",
                'frozen': len(self.freeze_threads),
                'scanning': self.is_scanning
            }


scanner_data = ScannerDataManager()


# ===== TELEGRAM БОТ =====
class TelegramBotManager:
    def __init__(self, data_manager: ScannerDataManager):
        self.data = data_manager
        self.bot_token = os.getenv('BOT_TOKEN', '')
        self.allowed_chat_id = int(os.getenv('ALLOWED_CHAT_ID', '0'))
        self.process_page = 0
        self.processes_per_page = 10
        self.process_filter = ""

        self.progress_message = None
        self.messages_to_delete = []  # Список сообщений для удаления

        if not self.bot_token:
            logger.warning("⚠️ BOT_TOKEN не найден в .env. Бот не запущен.")
            return

        self.bot = Bot(token=self.bot_token)
        self.dp = Dispatcher(storage=MemoryStorage())
        self._register_handlers()
        logger.info("✅ Telegram бот инициализирован (Aiogram 3.x)")

    def _register_handlers(self):
        self.dp.message.register(self.cmd_start, Command('start'))
        self.dp.message.register(self.cmd_help, Command('help'))
        self.dp.callback_query.register(self.on_callback)
        self.dp.message.register(self.on_text_message)

    def _check_access(self, user_id: int) -> bool:
        if user_id != self.allowed_chat_id:
            logger.warning(f" Отказано в доступе пользователю {user_id}")
            return False
        return True

    async def safe_send(self, message: Message, text: str, reply_markup=None, parse_mode="HTML", delete_old=False):
        """Безопасная отправка с удалением старых сообщений"""
        try:
            # Удаляем старые сообщения если нужно
            if delete_old and self.messages_to_delete:
                for msg_id in self.messages_to_delete:
                    try:
                        await self.bot.delete_message(message.chat.id, msg_id)
                    except:
                        pass
                self.messages_to_delete.clear()

            new_message = await message.answer(text, parse_mode=parse_mode, reply_markup=reply_markup)
            self.messages_to_delete.append(new_message.message_id)
            return new_message
        except TelegramRetryAfter as e:
            logger.warning(f"⏳ Flood wait {e.retry_after} сек")
            await asyncio.sleep(e.retry_after)
            return await self.safe_send(message, text, reply_markup, parse_mode, delete_old)
        except TelegramBadRequest as e:
            logger.error(f"⚠️ Bad request: {e}")
            return None
        except TelegramForbiddenError:
            logger.warning(f" Пользователь заблокировал бота")
            return None
        except Exception as e:
            logger.error(f"❌ Ошибка отправки: {type(e).__name__} - {e}")
            return None

    async def safe_edit(self, message: Message, text: str, reply_markup=None, parse_mode="HTML"):
        """Безопасное редактирование"""
        if message is None:
            return None
        try:
            await message.edit_text(text, parse_mode=parse_mode, reply_markup=reply_markup)
            return message
        except TelegramRetryAfter as e:
            logger.warning(f" Flood wait {e.retry_after} сек")
            await asyncio.sleep(e.retry_after)
            return await self.safe_edit(message, text, reply_markup, parse_mode)
        except TelegramBadRequest as e:
            if "not modified" in str(e).lower():
                return message
            logger.error(f"️ Ошибка редактирования: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Ошибка редактирования: {type(e).__name__} - {e}")
            return None

    def _get_main_keyboard(self) -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📊 Статус", callback_data="status")],
            [InlineKeyboardButton(text="🔍 Новый поиск", callback_data="new_scan")],
            [InlineKeyboardButton(text=" Точное значение", callback_data="next_prompt"),
             InlineKeyboardButton(text="📈 Изменилось", callback_data="changed")],
            [InlineKeyboardButton(text="📊 Не изменилось", callback_data="unchanged"),
             InlineKeyboardButton(text="🔄 Обновить", callback_data="refresh")],
            [InlineKeyboardButton(text="⏪ Назад", callback_data="back"),
             InlineKeyboardButton(text="⏩ Вперёд", callback_data="forward")],
            [InlineKeyboardButton(text="📋 Результаты", callback_data="list"),
             InlineKeyboardButton(text=" Сбросить", callback_data="reset")],
            [InlineKeyboardButton(text="❄️ Заморозить", callback_data="freeze_prompt"),
             InlineKeyboardButton(text="🔓 Разморозить всё", callback_data="unfreeze")],
        ])

    def _get_process_keyboard(self, processes: list, page: int, filter_text="") -> InlineKeyboardMarkup:
        start_idx = page * self.processes_per_page
        end_idx = start_idx + self.processes_per_page
        page_processes = processes[start_idx:end_idx]
        total_pages = (len(processes) + self.processes_per_page - 1) // self.processes_per_page

        keyboard = []
        if filter_text:
            keyboard.append([InlineKeyboardButton(text=f" Фильтр: '{filter_text}'", callback_data="noop")])

        for pid, name in page_processes:
            keyboard.append([InlineKeyboardButton(text=f"📱 {name} (PID: {pid})", callback_data=f"proc_{pid}")])

        nav_buttons = []
        if page > 0:
            nav_buttons.append(InlineKeyboardButton(text="⬅️", callback_data=f"proc_page_{page - 1}"))
        if total_pages > 1:
            nav_buttons.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop"))
        if page < total_pages - 1:
            nav_buttons.append(InlineKeyboardButton(text="➡️", callback_data=f"proc_page_{page + 1}"))
        if nav_buttons:
            keyboard.append(nav_buttons)

        keyboard.append([InlineKeyboardButton(text=" Отмена", callback_data="cancel")])
        return InlineKeyboardMarkup(inline_keyboard=keyboard)

    def _get_types_keyboard(self) -> InlineKeyboardMarkup:
        keyboard = []
        type_items = list(SCAN_TYPES.items())
        for i in range(0, len(type_items), 2):
            row = []
            for key, info in type_items[i:i + 2]:
                selected = key in self.data.selected_types
                short_name = info['name'][:30]
                row.append(InlineKeyboardButton(
                    text=f"{'✅' if selected else '❌'} {short_name}",
                    callback_data=f"type_{key}"
                ))
            keyboard.append(row)
        keyboard.append([InlineKeyboardButton(text="✅ Выбрать все", callback_data="types_all")])
        keyboard.append([InlineKeyboardButton(text=" Далее", callback_data="types_done")])
        keyboard.append([InlineKeyboardButton(text=" Отмена", callback_data="cancel")])
        return InlineKeyboardMarkup(inline_keyboard=keyboard)

    def _get_search_mode_keyboard(self) -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Да, знаю точное значение", callback_data="search_exact")],
            [InlineKeyboardButton(text="❌ Нет, поиск неизвестного", callback_data="search_unknown")],
            [InlineKeyboardButton(text="↩️ Назад", callback_data="back_to_types")],
        ])

    def _get_results_keyboard(self, results_list: list) -> InlineKeyboardMarkup:
        """Создаёт клавиатуру с результатами для редактирования"""
        keyboard = []
        # Показываем первые 10 результатов
        for i, (addr, type_key, val) in enumerate(results_list[:10]):
            t = SCAN_TYPES[type_key]
            val_str = f"{val:.4f}" if t['py'] == 'float' else str(val)
            keyboard.append([
                InlineKeyboardButton(
                    text=f" 0x{addr:X} [{t['name'][:20]}] = {val_str}",
                    callback_data=f"edit_{addr}_{type_key}"
                )
            ])

        if len(results_list) > 10:
            keyboard.append([InlineKeyboardButton(text=f"...и ещё {len(results_list) - 10}", callback_data="noop")])

        keyboard.append([InlineKeyboardButton(text="↩️ Назад в меню", callback_data="back_to_menu")])
        return InlineKeyboardMarkup(inline_keyboard=keyboard)

    async def cmd_start(self, message: Message):
        if not self._check_access(message.from_user.id):
            return

        # Очищаем клавиатуру ReplyKeyboard и старые сообщения
        self.messages_to_delete.clear()

        status = self.data.get_status()
        text = (
            f"🎮 <b>Memory Scanner v1.0</b>\n\n"
            f"🎯 <b>Процесс:</b> {status['process']}\n"
            f"📊 <b>Типов:</b> {status['types']}\n"
            f"📋 <b>Результатов:</b> {status['results']}\n"
            f"📜 <b>История:</b> {status['history']}\n"
            f"❄️ <b>Заморожено:</b> {status['frozen']}\n\n"
            f"Нажми кнопку ниже чтобы начать:"
        )

        # Используем ReplyKeyboardRemove() для очистки кнопок под полем ввода
        await message.answer(
            text,
            parse_mode="HTML",
            reply_markup=self._get_main_keyboard()
        )

    async def cmd_help(self, message: Message):
        if not self._check_access(message.from_user.id):
            return
        text = (
            " <b>Как использовать:</b>\n\n"
            "1️⃣ Нажми <b>🔍 Новый поиск</b>\n"
            "2️ Выбери процесс (кнопки ️➡️ для навигации)\n"
            "   • Или напиши имя процесса для поиска\n"
            "3️ Выбери типы данных (галочки ✅)\n"
            "4️⃣ Выбери режим поиска:\n"
            "   • <b>Да, знаю точное значение</b> — введи число\n"
            "   • <b>Нет, поиск неизвестного</b> — найдёт всё\n"
            "5️⃣ Следи за прогрессом (обновляется каждые 3 сек)\n"
            "6️⃣ После поиска нажми на адрес чтобы изменить значение\n"
            "7️⃣ Фильтруй результаты:\n"
            "   •  Изменилось\n"
            "   • 📊 Не изменилось\n"
            "   • 🔄 Обновить значения\n\n"
            "8️⃣ Управляй историей: ⏪⏩\n"
            "9️⃣ Замораживай значения: ❄️"
        )
        await self.safe_send(message, text, delete_old=True)

    async def on_callback(self, callback: CallbackQuery):
        try:
            await callback.answer()
        except Exception:
            pass

        user_id = callback.from_user.id
        if not self._check_access(user_id):
            return

        data = callback.data
        msg = callback.message

        try:
            if data == "status":
                await self.show_status(msg)
            elif data == "new_scan":
                await self.start_new_scan(msg)
            elif data.startswith("proc_page_"):
                page = int(data.split("_")[-1])
                self.process_page = page
                await self.show_process_selection(msg)
            elif data.startswith("proc_"):
                pid = int(data.split("_")[1])
                await self.select_process(msg, pid)
            elif data.startswith("type_"):
                type_key = data.split("_")[1]
                await self.toggle_type(msg, type_key)
            elif data == "types_all":
                await self.select_all_types(msg)
            elif data == "types_done":
                await self.show_search_mode(msg)
            elif data == "search_exact":
                await self.ask_for_value(msg)
            elif data == "search_unknown":
                await self.start_unknown_scan(msg)
            elif data == "back_to_types":
                await self.show_types_selection(msg)
            elif data == "next_prompt":
                await self.ask_for_next_value(msg)
            elif data == "changed":
                await self.filter_changed(msg)
            elif data == "unchanged":
                await self.filter_unchanged(msg)
            elif data == "refresh":
                await self.refresh_values(msg)
            elif data == "back":
                await self.go_back(msg)
            elif data == "forward":
                await self.go_forward(msg)
            elif data == "list":
                await self.show_results(msg)
            elif data == "reset":
                await self.reset_results(msg)
            elif data == "freeze_prompt":
                await self.ask_for_freeze(msg)
            elif data == "unfreeze":
                await self.unfreeze_all(msg)
            elif data == "cancel":
                await self.cancel_operation(msg)
            elif data == "back_to_menu":
                await self.cmd_start(msg)
            elif data.startswith("edit_"):
                # Обработка редактирования адреса: edit_ADDR_TYPEKEY
                parts = data.split("_")
                addr = int(parts[1], 16)
                type_key = parts[2]
                await self.edit_address_value(msg, addr, type_key)
            elif data == "noop":
                pass
        except Exception as e:
            logger.error(f"❌ Ошибка обработки callback {data}: {e}")

    async def on_text_message(self, message: Message):
        if not self._check_access(message.from_user.id):
            return
        if message.text and not message.text.startswith('/'):
            try:
                with self.data.lock:
                    if self.data.is_scanning:
                        await message.reply("⏳ Сейчас идёт сканирование, подождите...")
                        return

                processes = get_processes()
                if any(message.text.lower() in name.lower() for _, name in processes):
                    self.process_filter = message.text
                    self.process_page = 0
                    await self.show_process_selection(message)
                    return

                value = message.text.strip()
                float(value)
                await self.perform_scan(message, value)
            except ValueError:
                await self.safe_send(message,
                                     "❌ Введите корректное число (например: 850000 или 15.5)\nИли имя процесса для поиска",
                                     delete_old=True)
            except Exception as e:
                logger.error(f"❌ Ошибка обработки текста: {e}")
                await self.safe_send(message, f"❌ Ошибка: {e}", delete_old=True)

    async def show_status(self, message: Message):
        status = self.data.get_status()
        text = (
            f"📊 <b>Статус сканера:</b>\n\n"
            f"🎯 Процесс: <code>{status['process']}</code>\n"
            f"🔍 Типов данных: {status['types']}\n"
            f"📋 Результатов: {status['results']}\n"
            f" История: {status['history']}\n"
            f"❄️ Заморожено: {status['frozen']}\n"
            f"⏳ Сканирование: {'Да' if status['scanning'] else 'Нет'}"
        )
        await self.safe_send(message, text, self._get_main_keyboard(), delete_old=True)

    async def start_new_scan(self, message: Message):
        with self.data.lock:
            if not self.data.pm:
                await self.show_process_selection(message)
            else:
                await self.show_types_selection(message)

    async def show_process_selection(self, message: Message):
        try:
            processes = get_processes(self.process_filter)
            if not processes:
                filter_info = ""
                if self.process_filter:
                    filter_info = f" по фильтру '{self.process_filter}'"
                await self.safe_send(message,
                                     f"❌ Процессы не найдены{filter_info}.\nЗапусти программу сначала или введи другое имя.",
                                     delete_old=True)
                return

            text = f" <b>Выбери процесс ({len(processes)} найдено):</b>\n"
            if self.process_filter:
                text += f"\n Фильтр: <code>{self.process_filter}</code>\n"
            total_pages = (len(processes) + self.processes_per_page - 1) // self.processes_per_page
            text += f"\nСтраница {self.process_page + 1} из {total_pages}\n\n <i>Напиши имя процесса для поиска</i>"

            await self.safe_send(message, text,
                                 self._get_process_keyboard(processes, self.process_page, self.process_filter),
                                 delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка show_process_selection: {e}")

    async def select_process(self, message: Message, pid: int):
        try:
            processes = get_processes()
            proc = next((p for p in processes if p[0] == pid), None)
            if not proc:
                await self.safe_send(message, "❌ Процесс не найден", delete_old=True)
                return

            with self.data.lock:
                self.data.pm = pymem.Pymem()
                self.data.pm.open_process_from_id(pid)
                self.data.process_name = proc[1]
                self.data.process_pid = pid

            self.data.gui_update_queue.put({
                'type': 'process_selected',
                'name': proc[1],
                'pid': pid
            })

            await self.safe_send(message,
                                 f"✅ Выбран процесс: <code>{proc[1]}</code> (PID: {pid})\n\nТеперь выбери типы данных:",
                                 self._get_types_keyboard(), delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка select_process: {e}")
            await self.safe_send(message, f"❌ Ошибка подключения: {e}", delete_old=True)

    async def show_types_selection(self, message: Message):
        text = "⚙️ <b>Выбери типы данных для поиска:</b>\n\nОтмечай ✅ нужные типы:"
        await self.safe_send(message, text, self._get_types_keyboard(), delete_old=True)

    async def toggle_type(self, message: Message, type_key: str):
        try:
            with self.data.lock:
                if type_key in self.data.selected_types:
                    self.data.selected_types.remove(type_key)
                else:
                    self.data.selected_types.add(type_key)
            await message.edit_reply_markup(reply_markup=self._get_types_keyboard())
        except Exception as e:
            logger.error(f"❌ Ошибка toggle_type: {e}")

    async def select_all_types(self, message: Message):
        try:
            with self.data.lock:
                if len(self.data.selected_types) == len(SCAN_TYPES):
                    self.data.selected_types = set()
                else:
                    self.data.selected_types = set(SCAN_TYPES.keys())
            await message.edit_reply_markup(reply_markup=self._get_types_keyboard())
        except Exception as e:
            logger.error(f"❌ Ошибка select_all_types: {e}")

    async def show_search_mode(self, message: Message):
        text = "🤔 <b>Ты знаешь точное значение для поиска?</b>\n\nВыбери режим:"
        await self.safe_send(message, text, self._get_search_mode_keyboard(), delete_old=True)

    async def ask_for_value(self, message: Message):
        await self.safe_send(message,
                             " <b>Введите значение для поиска:</b>\n\nМожно вводить:\n• Целые числа: 850000\n• Дробные: 15.5\n• С точкой: 3.14\n\nПросто отправь число:",
                             delete_old=True)

    async def ask_for_next_value(self, message: Message):
        with self.data.lock:
            if not self.data.scan_results:
                await self.safe_send(message, "❌ Сначала выполни поиск!", delete_old=True)
                return
        await self.safe_send(message, " <b>Введите новое точное значение:</b>\n\nПросто отправь число:",
                             delete_old=True)

    async def perform_scan(self, message: Message, search_value: str):
        try:
            with self.data.lock:
                if not self.data.pm or not self.data.selected_types:
                    await self.safe_send(message, "❌ Сначала выбери процесс и типы данных!", delete_old=True)
                    return
                self.data.is_scanning = True

            self.data.gui_update_queue.put({
                'type': 'scan_started',
                'value': search_value
            })

            progress_msg = await self.safe_send(message, f"🔍 <b>Начинаю поиск: '{search_value}'</b>\n\n⏳ Подготовка...",
                                                delete_old=True)
            self.progress_message = progress_msg

            threading.Thread(target=self._do_scan_thread, args=(search_value, False), daemon=True).start()
        except Exception as e:
            logger.error(f" Ошибка perform_scan: {e}")
            with self.data.lock:
                self.data.is_scanning = False

    async def start_unknown_scan(self, message: Message):
        try:
            with self.data.lock:
                if not self.data.pm or not self.data.selected_types:
                    await self.safe_send(message, "❌ Сначала выбери процесс и типы данных!", delete_old=True)
                    return
                self.data.is_scanning = True

            self.data.gui_update_queue.put({
                'type': 'scan_started',
                'value': 'неизвестное'
            })

            progress_msg = await self.safe_send(message, "🔍 <b>Поиск неизвестного значения</b>\n\n⏳ Подготовка...",
                                                delete_old=True)
            self.progress_message = progress_msg

            threading.Thread(target=self._do_scan_thread, args=('', True), daemon=True).start()
        except Exception as e:
            logger.error(f"❌ Ошибка start_unknown_scan: {e}")
            with self.data.lock:
                self.data.is_scanning = False

    def _do_scan_thread(self, search_value: str, is_unknown: bool):
        try:
            start_time = time.time()
            last_update = start_time
            new_results = {}
            new_history = {}
            regions_checked = 0
            total_entries = 0
            total_bytes = 0

            with self.data.lock:
                pm = self.data.pm
                selected_types = set(self.data.selected_types)

            regions = get_memory_regions(pm.process_handle)
            valid_regions = [r for r in regions if r['State'] == 0x1000 and r['Protect'] in (0x04, 0x40, 0x02)]
            total_regions = len(valid_regions)

            for type_idx, type_key in enumerate(selected_types):
                with self.data.lock:
                    if not self.data.is_scanning:
                        break

                t = SCAN_TYPES[type_key]

                if is_unknown:
                    target_bytes = None
                else:
                    parsed_value, err = parse_search_value(type_key, search_value)
                    if err:
                        continue
                    try:
                        target_bytes = value_to_bytes(type_key, parsed_value)
                    except:
                        continue

                for region_idx, region in enumerate(valid_regions):
                    with self.data.lock:
                        if not self.data.is_scanning:
                            break

                    base_addr = region['BaseAddress']
                    if not base_addr or region['RegionSize'] < t['size']:
                        continue

                    try:
                        data = pm.read_bytes(base_addr, min(region['RegionSize'], 64 * 1024 * 1024))
                    except:
                        continue

                    regions_checked += 1
                    total_bytes += len(data)

                    current_time = time.time()
                    if current_time - last_update >= 3.0:
                        elapsed = current_time - start_time
                        speed_mb = (total_bytes / (1024 * 1024)) / max(elapsed, 0.1)
                        percent = min(100, ((type_idx + region_idx / max(total_regions, 1)) / max(len(selected_types),
                                                                                                  1)) * 100)

                        progress_text = (
                            f" <b>Сканирование...</b>\n\n"
                            f"📊 <b>Прогресс:</b> {percent:.1f}%\n"
                            f" Скорость: {speed_mb:.1f} MB/s\n"
                            f" Регионов: {regions_checked}/{total_regions}\n"
                            f"💾 Найдено: {total_entries} записей\n"
                            f"⏱ Время: {elapsed:.1f} сек"
                        )

                        self.data.bot_progress_queue.put({
                            'type': 'progress',
                            'text': progress_text,
                            'percent': percent
                        })

                        self.data.gui_update_queue.put({
                            'type': 'progress',
                            'percent': percent,
                            'speed_mb': speed_mb,
                            'regions': regions_checked,
                            'total_regions': total_regions,
                            'entries': total_entries,
                            'elapsed': elapsed
                        })

                        last_update = current_time

                    pos = 0
                    while pos <= len(data) - t['size']:
                        if is_unknown or data[pos:pos + t['size']] == target_bytes:
                            addr = base_addr + pos
                            val = read_value(type_key, data, pos)
                            if val is not None:
                                if addr not in new_results:
                                    new_results[addr] = {}
                                    new_history[addr] = {}
                                new_results[addr][type_key] = val
                                new_history[addr][type_key] = val
                                total_entries += 1
                            pos += t['size']
                        else:
                            pos += 1

            elapsed = time.time() - start_time
            with self.data.lock:
                self.data.scan_results = new_results
                self.data.scan_history = new_history
                self.data.changed_addrs.clear()
                self.data.push_history(
                    f"Поиск '{search_value if not is_unknown else 'неизв.'}' → {total_entries} записей")
                self.data.is_scanning = False

            mb = total_bytes / (1024 * 1024)
            speed = (total_bytes / (1024 * 1024)) / max(elapsed, 0.1)
            result_text = (
                f"✅ <b>Поиск завершён!</b>\n\n"
                f"📊 Найдено: <b>{total_entries}</b> записей\n"
                f"⏱ Время: {elapsed:.1f} сек\n"
                f"⚡ Скорость: {speed:.1f} MB/s\n"
                f"💾 Просканировано: {mb:.1f} MB\n"
                f" Регионов: {regions_checked}\n\n"
                f"<i>Нажми на адрес чтобы изменить значение</i>"
            )

            self.data.bot_progress_queue.put({
                'type': 'result',
                'text': result_text
            })

            self.data.gui_update_queue.put({
                'type': 'scan_complete',
                'count': total_entries,
                'elapsed': elapsed,
                'regions': regions_checked,
                'total_bytes': total_bytes
            })

        except Exception as e:
            logger.error(f"❌ Ошибка в потоке сканирования: {e}")
            with self.data.lock:
                self.data.is_scanning = False

            self.data.bot_progress_queue.put({
                'type': 'error',
                'text': f"❌ Ошибка сканирования: {e}"
            })

            self.data.gui_update_queue.put({
                'type': 'scan_error',
                'error': str(e)
            })

    async def _progress_updater(self):
        logger.info("🔄 Запущен progress updater")
        while True:
            try:
                while not self.data.bot_progress_queue.empty():
                    update = self.data.bot_progress_queue.get_nowait()

                    if self.progress_message is None:
                        continue

                    if update['type'] == 'progress':
                        await self.safe_edit(self.progress_message, update['text'])
                    elif update['type'] == 'result':
                        await self.safe_edit(self.progress_message, update['text'], self._get_main_keyboard())
                        self.progress_message = None
                    elif update['type'] == 'error':
                        await self.safe_edit(self.progress_message, update['text'])
                        self.progress_message = None

                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Ошибка в progress updater: {e}")
                await asyncio.sleep(1)

    async def edit_address_value(self, message: Message, addr: int, type_key: str):
        """Редактирование значения по адресу"""
        try:
            t = SCAN_TYPES[type_key]

            with self.data.lock:
                if addr not in self.data.scan_results or type_key not in self.data.scan_results[addr]:
                    await self.safe_send(message, "❌ Адрес не найден в результатах!", delete_old=True)
                    return
                current_val = self.data.scan_results[addr][type_key]

            val_str = f"{current_val:.6f}" if t['py'] == 'float' else str(current_val)

            await self.safe_send(
                message,
                f"️ <b>Редактирование значения</b>\n\n"
                f"📍 Адрес: <code>0x{addr:X}</code>\n"
                f"📊 Тип: {t['name']}\n"
                f" Текущее: <code>{val_str}</code>\n\n"
                f"<b>Введите новое значение:</b>",
                delete_old=True
            )

            # Ждём ввод нового значения
            # Это упрощённая версия — в реальном боте нужно использовать FSM
            # Для простоты просто отправляем сообщение что нужно ввести значение

        except Exception as e:
            logger.error(f"❌ Ошибка edit_address_value: {e}")
            await self.safe_send(message, f"❌ Ошибка: {e}", delete_old=True)

    async def filter_changed(self, message: Message):
        try:
            with self.data.lock:
                if not self.data.scan_results:
                    await self.safe_send(message, "❌ Нет результатов для фильтрации!", delete_old=True)
                    return

            progress_msg = await self.safe_send(message, "🔄 <b>Фильтрация: ищем изменившиеся...</b>", delete_old=True)
            self.progress_message = progress_msg

            def do_filter():
                try:
                    with self.data.lock:
                        scan_copy = copy.deepcopy(self.data.scan_results)
                        pm = self.data.pm

                    new_results = {}
                    changed = 0
                    unchanged = 0

                    for addr, types in scan_copy.items():
                        for type_key, baseline_val in types.items():
                            t = SCAN_TYPES[type_key]
                            try:
                                data = pm.read_bytes(addr, t['size'])
                                current_val = read_value(type_key, data, 0)
                                if current_val is not None and baseline_val is not None and current_val != baseline_val:
                                    if addr not in new_results:
                                        new_results[addr] = {}
                                    new_results[addr][type_key] = current_val
                                    changed += 1
                                else:
                                    unchanged += 1
                            except:
                                pass

                    total = sum(len(t) for t in new_results.values())
                    with self.data.lock:
                        self.data.scan_results = new_results
                        self.data.changed_addrs.clear()
                        self.data.push_history(f"Изменилось: {total}")

                    self.data.gui_update_queue.put({'type': 'results_updated'})

                    result_text = f"✅ <b>Фильтрация завершена</b>\n\n Изменилось: <b>{changed}</b>\n📊 Не изменилось: {unchanged}\n\n<b>Осталось:</b> {total}"
                    self.data.bot_progress_queue.put({'type': 'result', 'text': result_text})
                except Exception as e:
                    logger.error(f"❌ Ошибка filter_changed: {e}")
                    self.data.bot_progress_queue.put({'type': 'error', 'text': f"❌ Ошибка: {e}"})

            threading.Thread(target=do_filter, daemon=True).start()
        except Exception as e:
            logger.error(f"❌ Ошибка filter_changed: {e}")

    async def filter_unchanged(self, message: Message):
        try:
            with self.data.lock:
                if not self.data.scan_results:
                    await self.safe_send(message, "❌ Нет результатов!", delete_old=True)
                    return

            progress_msg = await self.safe_send(message, " <b>Фильтрация: ищем неизменившиеся...</b>", delete_old=True)
            self.progress_message = progress_msg

            def do_filter():
                try:
                    with self.data.lock:
                        scan_copy = copy.deepcopy(self.data.scan_results)
                        pm = self.data.pm

                    new_results = {}
                    for addr, types in scan_copy.items():
                        for type_key, baseline_val in types.items():
                            t = SCAN_TYPES[type_key]
                            try:
                                data = pm.read_bytes(addr, t['size'])
                                current_val = read_value(type_key, data, 0)
                                if current_val is not None and baseline_val is not None and current_val == baseline_val:
                                    if addr not in new_results:
                                        new_results[addr] = {}
                                    new_results[addr][type_key] = current_val
                            except:
                                pass

                    total = sum(len(t) for t in new_results.values())
                    with self.data.lock:
                        self.data.scan_results = new_results
                        self.data.changed_addrs.clear()
                        self.data.push_history(f"Не изменилось: {total}")

                    self.data.gui_update_queue.put({'type': 'results_updated'})

                    result_text = f"✅ <b>Фильтрация завершена</b>\n\n📊 <b>Неизменившихся:</b> {total}"
                    self.data.bot_progress_queue.put({'type': 'result', 'text': result_text})
                except Exception as e:
                    logger.error(f"❌ Ошибка filter_unchanged: {e}")
                    self.data.bot_progress_queue.put({'type': 'error', 'text': f"❌ Ошибка: {e}"})

            threading.Thread(target=do_filter, daemon=True).start()
        except Exception as e:
            logger.error(f"❌ Ошибка filter_unchanged: {e}")

    async def refresh_values(self, message: Message):
        try:
            with self.data.lock:
                if not self.data.scan_results:
                    await self.safe_send(message, "❌ Нет результатов!", delete_old=True)
                    return

            progress_msg = await self.safe_send(message, "🔄 <b>Обновление значений...</b>", delete_old=True)
            self.progress_message = progress_msg

            def do_refresh():
                try:
                    with self.data.lock:
                        scan_copy = copy.deepcopy(self.data.scan_results)
                        pm = self.data.pm

                    changed = 0
                    unchanged = 0
                    errors = 0
                    new_changed = set()

                    for addr, types in scan_copy.items():
                        for type_key, baseline_val in types.items():
                            t = SCAN_TYPES[type_key]
                            try:
                                data = pm.read_bytes(addr, t['size'])
                                current_val = read_value(type_key, data, 0)
                                if current_val is not None:
                                    if baseline_val is not None and current_val != baseline_val:
                                        new_changed.add(addr)
                                        changed += 1
                                    else:
                                        unchanged += 1
                                else:
                                    errors += 1
                            except:
                                errors += 1

                    with self.data.lock:
                        self.data.changed_addrs = new_changed
                        self.data.push_history(f"Обновлено (изм: {changed})")

                    self.data.gui_update_queue.put({'type': 'results_updated'})

                    result_text = f"✅ <b>Обновлено</b>\n\n Изменилось: {changed}\n Не изменилось: {unchanged}\n⚠️ Ошибок: {errors}"
                    self.data.bot_progress_queue.put({'type': 'result', 'text': result_text})
                except Exception as e:
                    logger.error(f" Ошибка refresh_values: {e}")
                    self.data.bot_progress_queue.put({'type': 'error', 'text': f"❌ Ошибка: {e}"})

            threading.Thread(target=do_refresh, daemon=True).start()
        except Exception as e:
            logger.error(f"❌ Ошибка refresh_values: {e}")

    async def go_back(self, message: Message):
        try:
            desc = self.data.go_back()
            if desc:
                self.data.gui_update_queue.put({'type': 'results_updated'})
                await self.safe_send(message, f" {desc}", self._get_main_keyboard(), delete_old=True)
            else:
                await self.safe_send(message, "❌ Нельзя вернуться дальше", delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка go_back: {e}")

    async def go_forward(self, message: Message):
        try:
            desc = self.data.go_forward()
            if desc:
                self.data.gui_update_queue.put({'type': 'results_updated'})
                await self.safe_send(message, f"⏩ {desc}", self._get_main_keyboard(), delete_old=True)
            else:
                await self.safe_send(message, "❌ Нельзя перейти вперёд", delete_old=True)
        except Exception as e:
            logger.error(f" Ошибка go_forward: {e}")

    async def show_results(self, message: Message):
        try:
            with self.data.lock:
                if not self.data.scan_results:
                    await self.safe_send(message, "📭 Список пуст", delete_old=True)
                    return
                results_copy = copy.deepcopy(self.data.scan_results)

            # Создаём список результатов для кнопок
            results_list = []
            for addr in sorted(results_copy.keys()):
                for type_key in sorted(results_copy[addr].keys()):
                    val = results_copy[addr][type_key]
                    results_list.append((addr, type_key, val))

            text = f"📋 <b>Результаты ({len(results_list)} записей):</b>\n\n"
            text += "<i>Нажми на адрес чтобы изменить значение</i>\n\n"

            # Показываем первые 5 результатов в тексте
            for i, (addr, type_key, val) in enumerate(results_list[:5]):
                t = SCAN_TYPES[type_key]
                val_str = f"{val:.4f}" if t['py'] == 'float' else str(val)
                text += f"<code>0x{addr:X}</code> [{t['name']}] = {val_str}\n"

            if len(results_list) > 5:
                text += f"\n...и ещё {len(results_list) - 5}"

            keyboard = self._get_results_keyboard(results_list)
            await self.safe_send(message, text, keyboard, delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка show_results: {e}")

    async def reset_results(self, message: Message):
        try:
            with self.data.lock:
                self.data.scan_results = {}
                self.data.scan_history = {}
                self.data.changed_addrs.clear()
                self.data.history.clear()
                self.data.history_index = -1

            self.data.gui_update_queue.put({'type': 'results_reset'})
            await self.safe_send(message, "🗑 <b>Все результаты сброшены</b>", self._get_main_keyboard(),
                                 delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка reset_results: {e}")

    async def ask_for_freeze(self, message: Message):
        try:
            with self.data.lock:
                if not self.data.scan_results:
                    await self.safe_send(message, "❌ Нет результатов!", delete_old=True)
                    return
            await self.safe_send(message,
                                 "❄️ <b>Заморозка значения</b>\n\nОтправь в формате:\n<code>адрес_hex значение</code>\n\nПример:\n<code>14742278 9999</code>",
                                 delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка ask_for_freeze: {e}")

    async def unfreeze_all(self, message: Message):
        try:
            with self.data.lock:
                for types in self.data.freeze_threads.values():
                    for thread, event in types.values():
                        event.set()
                self.data.freeze_threads.clear()

            self.data.gui_update_queue.put({'type': 'results_updated'})
            await self.safe_send(message, "🔓 <b>Все адреса разморожены</b>", self._get_main_keyboard(), delete_old=True)
        except Exception as e:
            logger.error(f"❌ Ошибка unfreeze_all: {e}")

    async def cancel_operation(self, message: Message):
        try:
            with self.data.lock:
                self.data.is_scanning = False

            self.data.gui_update_queue.put({'type': 'scan_cancelled'})
            await self.safe_send(message, "❌ <b>Операция отменена</b>", self._get_main_keyboard(), delete_old=True)
        except Exception as e:
            logger.error(f" Ошибка cancel_operation: {e}")

    def start(self):
        if not self.bot_token:
            return

        async def main():
            me = await self.bot.get_me()
            logger.info(f"🤖 Бот запущен: @{me.username} (ID: {me.id})")

            progress_task = asyncio.create_task(self._progress_updater())

            await self.dp.start_polling(self.bot, allowed_updates=self.dp.resolve_used_update_types())

            progress_task.cancel()

        def run_async_loop():
            try:
                asyncio.run(main())
            except Exception as e:
                logger.error(f"❌ Ошибка бота: {e}")

        threading.Thread(target=run_async_loop, daemon=True, name="AiogramBotThread").start()


# ===== GUI ПРИЛОЖЕНИЕ =====
class MemoryScannerApp:
    def __init__(self, root, data_manager: ScannerDataManager, bot_manager: TelegramBotManager):
        self.root = root
        self.data = data_manager
        self.bot = bot_manager

        self.root.title("Memory Scanner v1.0")
        self.root.geometry("1250x900")
        self.root.minsize(900, 650)
        self.root.resizable(True, True)

        self.setup_styles()
        self.process_panel_visible = False
        self.admin_ok = is_admin()

        if not self.admin_ok:
            self.build_no_admin_ui()
        else:
            self.build_ui()
            self.root.after(100, self.check_gui_queue)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f5f5f5')
        style.configure('TLabel', background='#f5f5f5', font=('Segoe UI', 9))
        style.configure('Title.TLabel', font=('Segoe UI', 11, 'bold'), background='#f5f5f5')
        style.configure('TLabelFrame', background='#f5f5f5', borderwidth=1)
        style.configure('TLabelFrame.Label', font=('Segoe UI', 9, 'bold'), background='#f5f5f5')
        style.configure('TButton', font=('Segoe UI', 9), padding=5)
        style.configure('Action.TButton', font=('Segoe UI', 9, 'bold'), padding=8)
        style.configure('TProgressbar', thickness=20, background='#4CAF50')
        style.configure('Treeview', font=('Consolas', 9), rowheight=22)
        style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))

    def check_gui_queue(self):
        try:
            while not self.data.gui_update_queue.empty():
                update = self.data.gui_update_queue.get_nowait()
                self.process_gui_update(update)
        except queue.Empty:
            pass
        except Exception as e:
            logger.error(f"❌ Ошибка check_gui_queue: {e}")

        self.root.after(100, self.check_gui_queue)

    def process_gui_update(self, update):
        try:
            update_type = update.get('type')

            if update_type == 'process_selected':
                self.proc_status_label.config(
                    text=f"✅ {update['name']} (PID: {update['pid']})",
                    foreground='#2e7d32'
                )

            elif update_type == 'scan_started':
                self.search_var.set(update['value'])
                self.progress_var.set(0)
                self.progress_label.config(
                    text=f"🔍 Поиск: {update['value']}...",
                    foreground='#f57c00'
                )

            elif update_type == 'progress':
                self.progress_var.set(update['percent'])
                self.progress_label.config(
                    text=f"{update['percent']:.0f}% | {update['speed_mb']:.1f} MB/s | {update['regions']}/{update['total_regions']} рег.",
                    foreground='#f57c00'
                )

            elif update_type == 'scan_complete':
                self.progress_var.set(100)
                mb = update['total_bytes'] / (1024 * 1024)
                self.progress_label.config(
                    text=f"✅ {mb:.1f} MB | {update['regions']} рег. за {update['elapsed']:.1f}с",
                    foreground='#2e7d32'
                )
                self.refresh_tree()

            elif update_type == 'scan_error':
                self.progress_label.config(text=f"❌ Ошибка: {update['error']}", foreground='#d32f2f')

            elif update_type == 'scan_cancelled':
                self.progress_label.config(text="❌ Отменено", foreground='#d32f2f')

            elif update_type == 'results_updated':
                self.refresh_tree()
                self.update_history_buttons()

            elif update_type == 'results_reset':
                self.refresh_tree()
                self.update_history_buttons()
                self.progress_var.set(0)
                self.progress_label.config(text="Готов", foreground='#2e7d32')
        except Exception as e:
            logger.error(f"❌ Ошибка process_gui_update: {e}")

    def build_no_admin_ui(self):
        self.root.geometry("550x400")
        self.root.resizable(False, False)
        self.root.configure(bg='#f5f5f5')
        main_frame = ttk.Frame(self.root, padding=30)
        main_frame.pack(fill='both', expand=True)
        ttk.Label(main_frame, text="⚠️ Требуются права администратора", style='Title.TLabel',
                  foreground='#d32f2f').pack(pady=20)
        ttk.Label(main_frame, text="Для работы с памятью процессов\nнеобходимы права администратора.",
                  font=('Segoe UI', 11), justify='center').pack(pady=15)
        ttk.Button(main_frame, text=" Запустить от имени администратора", style='Action.TButton',
                   command=self.on_run_as_admin).pack(pady=20, ipadx=30, ipady=12)
        ttk.Button(main_frame, text="⚠️ Продолжить без прав", command=self.on_continue_without_admin).pack(pady=5)
        self.status_msg = ttk.Label(main_frame, text="", font=('Segoe UI', 9), foreground='gray')
        self.status_msg.pack(pady=5)

    def on_run_as_admin(self):
        self.status_msg.config(text=" Запуск...", foreground='#1976d2')
        self.root.update()
        success, error = restart_as_admin()
        if not success:
            self.status_msg.config(text=f"❌ Ошибка: {error}", foreground='#d32f2f')
            messagebox.showerror("Ошибка", f"Не удалось: {error}\n\nПопробуй правый клик → Запуск от админа")

    def on_continue_without_admin(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.admin_ok = False
        self.build_ui()
        self.root.after(100, self.check_gui_queue)

    def build_ui(self):
        self.root.configure(bg='#f5f5f5')
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill='x', padx=8, pady=8)

        self.proc_btn = ttk.Button(top_frame, text="📋 Процессы", command=self.toggle_process_panel)
        self.proc_btn.pack(side='left', padx=2)
        self.proc_status_label = ttk.Label(top_frame, text="Процесс не выбран", foreground='#d32f2f',
                                           font=('Segoe UI', 9, 'bold'))
        self.proc_status_label.pack(side='left', padx=10)

        self.admin_label = ttk.Label(top_frame, text="🔑 Админ: ✅" if self.admin_ok else "⚠️ Админ: ",
                                     font=('Segoe UI', 9, 'bold'), foreground='#2e7d32' if self.admin_ok else '#f57c00')
        self.admin_label.pack(side='right', padx=5)

        self.proc_panel = ttk.Frame(self.root, relief='groove', borderwidth=2)
        proc_search_frame = ttk.Frame(self.proc_panel)
        proc_search_frame.pack(fill='x', padx=8, pady=8)
        ttk.Label(proc_search_frame, text="🔍 Поиск:").pack(side='left', padx=5)
        self.proc_search_var = tk.StringVar()
        self.proc_search_var.trace_add('write', lambda *args: self.refresh_processes(self.proc_search_var.get()))
        ttk.Entry(proc_search_frame, textvariable=self.proc_search_var, width=30).pack(side='left', padx=5, fill='x',
                                                                                       expand=True)

        proc_list_frame = ttk.Frame(self.proc_panel)
        proc_list_frame.pack(fill='both', expand=True, padx=8, pady=5)
        self.proc_listbox = tk.Listbox(proc_list_frame, height=10, selectmode='browse', font=('Consolas', 10))
        self.proc_listbox.pack(side='left', fill='both', expand=True)
        self.proc_listbox.bind('<Double-1>', lambda e: self.on_process_select())
        ttk.Scrollbar(proc_list_frame, orient='vertical', command=self.proc_listbox.yview).pack(side='right', fill='y')
        self.proc_listbox.config(yscrollcommand=lambda f, l: self.proc_listbox.yview)

        ttk.Button(self.proc_panel, text="✅ Выбрать", command=self.on_process_select).pack(side='left', padx=8, pady=5)
        ttk.Button(self.proc_panel, text=" Закрыть", command=self.toggle_process_panel).pack(side='right', padx=8,
                                                                                             pady=5)
        self.refresh_processes()

        search_frame = ttk.LabelFrame(self.root, text="Параметры поиска", padding=8)
        search_frame.pack(fill='x', padx=8, pady=5)

        types_frame = ttk.LabelFrame(search_frame, text="Типы данных", padding=5)
        types_frame.pack(fill='x', pady=5)
        self.type_vars = {}
        type_check_frame = ttk.Frame(types_frame)
        type_check_frame.pack(fill='x')
        for col, (key, info) in enumerate(SCAN_TYPES.items()):
            var = tk.BooleanVar(value=True)
            self.type_vars[key] = var
            ttk.Checkbutton(type_check_frame, text=info['name'], variable=var, command=self.update_selected_types).grid(
                row=col // 3, column=col % 3, sticky='w', padx=10, pady=3)

        value_frame = ttk.Frame(search_frame)
        value_frame.pack(fill='x', pady=8)
        ttk.Label(value_frame, text="Значение:", font=('Segoe UI', 9, 'bold')).pack(side='left', padx=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(value_frame, textvariable=self.search_var, width=25, font=('Consolas', 11))
        self.search_entry.pack(side='left', padx=5)
        self.search_entry.bind('<Return>', lambda e: self.first_scan_exact())

        filter_frame = ttk.Frame(search_frame)
        filter_frame.pack(fill='x', pady=5)
        self.btn_back = ttk.Button(filter_frame, text="⏪ Назад", command=self.go_back, state='disabled')
        self.btn_back.pack(side='left', padx=2)
        self.btn_forward = ttk.Button(filter_frame, text=" Вперёд", command=self.go_forward, state='disabled')
        self.btn_forward.pack(side='left', padx=2)
        ttk.Button(filter_frame, text=" Точное", command=self.next_scan_exact).pack(side='left', padx=2)
        ttk.Button(filter_frame, text=" Изменилось", command=self.filter_changed).pack(side='left', padx=2)
        ttk.Button(filter_frame, text=" Не изм.", command=self.filter_unchanged).pack(side='left', padx=2)
        self.btn_refresh = ttk.Button(filter_frame, text=" Обновить", command=self.refresh_values)
        self.btn_refresh.pack(side='left', padx=2)
        ttk.Button(filter_frame, text="🗑 Сброс", command=self.reset_results).pack(side='left', padx=2)
        self.history_label = ttk.Label(filter_frame, text="📜 0/0", foreground='#666')
        self.history_label.pack(side='right', padx=10)

        progress_frame = ttk.Frame(search_frame)
        progress_frame.pack(fill='x', pady=5)
        self.progress_var = tk.DoubleVar(value=0)
        ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100).pack(side='left', fill='x',
                                                                                      expand=True, padx=5)
        self.progress_label = ttk.Label(progress_frame, text="Готов", width=60, foreground='#2e7d32')
        self.progress_label.pack(side='right', padx=5)

        bottom_frame = ttk.LabelFrame(self.root, text="Результаты", padding=8)
        bottom_frame.pack(fill='both', expand=True, padx=8, pady=5)

        columns = ('addr', 'type', 'value', 'old_value', 'hex', 'frozen')
        self.tree = ttk.Treeview(bottom_frame, columns=columns, show='headings', selectmode='extended')
        for col, width in zip(columns, [120, 200, 110, 110, 120, 60]):
            self.tree.heading(col, text=col.capitalize(), command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=width, anchor='w' if col != 'frozen' else 'center')

        self.tree.tag_configure('changed', foreground='#d32f2f')
        self.tree.tag_configure('frozen_tag', foreground='#1976d2')
        self.tree.tag_configure('normal', foreground='#212121')

        self.tree.pack(side='top', fill='both', expand=True)
        ttk.Scrollbar(bottom_frame, orient='vertical', command=self.tree.yview).pack(side='right', fill='y')
        self.tree.config(yscrollcommand=lambda f, l: self.tree.yview)

        result_btn_frame = ttk.Frame(bottom_frame)
        result_btn_frame.pack(fill='x', pady=5)
        ttk.Button(result_btn_frame, text="✏️ Записать", command=self.write_selected).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text="️ Заморозить", command=self.freeze_selected).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text="🔓 Разморозить", command=self.unfreeze_selected).pack(side='left', padx=2)
        ttk.Button(result_btn_frame, text="📋 Копировать", command=self.copy_address).pack(side='left', padx=2)
        self.result_count = ttk.Label(result_btn_frame, text="Адресов: 0", font=('Segoe UI', 9, 'bold'))
        self.result_count.pack(side='right', padx=10)

    def toggle_process_panel(self):
        if self.process_panel_visible:
            self.proc_panel.pack_forget()
            self.proc_btn.config(text=" Процессы")
            self.process_panel_visible = False
        else:
            self.proc_panel.pack(fill='x', padx=8, pady=3)
            self.proc_btn.config(text="📋 Скрыть процессы")
            self.process_panel_visible = True
            self.proc_search_var.set("")
            self.refresh_processes()

    def refresh_processes(self, filter_text=''):
        self.proc_listbox.delete(0, 'end')
        for pid, name in get_processes(filter_text):
            self.proc_listbox.insert('end', f"{name}  (PID: {pid})")

    def on_process_select(self):
        selection = self.proc_listbox.curselection()
        if not selection:
            return
        processes = get_processes(self.proc_search_var.get())
        if selection[0] >= len(processes):
            return
        pid, name = processes[selection[0]]
        try:
            with self.data.lock:
                self.data.pm = pymem.Pymem()
                self.data.pm.open_process_from_id(pid)
                self.data.process_name = name
                self.data.process_pid = pid
            self.proc_status_label.config(text=f"✅ {name} (PID: {pid})", foreground='#2e7d32')
            self.toggle_process_panel()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться:\n{e}")

    def update_selected_types(self):
        with self.data.lock:
            self.data.selected_types = {k for k, v in self.type_vars.items() if v.get()}

    def first_scan_exact(self):
        with self.data.lock:
            if not self.data.pm or not self.data.selected_types:
                messagebox.showwarning("Внимание", "Выбери процесс и тип данных!")
                return
        search_value = self.search_var.get().strip()
        if not search_value:
            return

        valid = any(parse_search_value(tk, search_value)[1] is None for tk in self.data.selected_types)
        if not valid:
            messagebox.showwarning("Внимание", f"Значение '{search_value}' не подходит!")
            return

        with self.data.lock:
            self.data.is_scanning = True
        self.progress_var.set(0)
        self.progress_label.config(text="Сканирование...", foreground='#f57c00')
        threading.Thread(target=self._do_first_scan, args=(search_value, False), daemon=True).start()

    def _do_first_scan(self, search_value, is_unknown):
        try:
            start_time = time.time()
            new_results = {}
            new_history = {}
            regions_checked = 0
            total_entries = 0
            total_bytes = 0

            with self.data.lock:
                pm = self.data.pm
                selected_types = set(self.data.selected_types)

            regions = get_memory_regions(pm.process_handle)
            valid_regions = [r for r in regions if r['State'] == 0x1000 and r['Protect'] in (0x04, 0x40, 0x02)]

            for type_key in selected_types:
                t = SCAN_TYPES[type_key]
                if is_unknown:
                    target_bytes = None
                else:
                    parsed_value, err = parse_search_value(type_key, search_value)
                    if err:
                        continue
                    try:
                        target_bytes = value_to_bytes(type_key, parsed_value)
                    except:
                        continue

                for region in valid_regions:
                    with self.data.lock:
                        if not self.data.is_scanning:
                            break

                    base_addr = region['BaseAddress']
                    if not base_addr or region['RegionSize'] < t['size']:
                        continue

                    try:
                        data = pm.read_bytes(base_addr, min(region['RegionSize'], 64 * 1024 * 1024))
                    except:
                        continue

                    regions_checked += 1
                    total_bytes += len(data)

                    pos = 0
                    while pos <= len(data) - t['size']:
                        if is_unknown or data[pos:pos + t['size']] == target_bytes:
                            addr = base_addr + pos
                            val = read_value(type_key, data, pos)
                            if val is not None:
                                if addr not in new_results:
                                    new_results[addr] = {}
                                    new_history[addr] = {}
                                new_results[addr][type_key] = val
                                new_history[addr][type_key] = val
                                total_entries += 1
                            pos += t['size']
                        else:
                            pos += 1

            with self.data.lock:
                self.data.scan_results = new_results
                self.data.scan_history = new_history
                self.data.changed_addrs.clear()
                self.data.push_history(f"Поиск: '{search_value if not is_unknown else 'неизв.'}' → {total_entries}")

            elapsed = time.time() - start_time
            self.root.after(0, lambda: self._scan_complete(total_entries, elapsed, regions_checked, total_bytes))
        except Exception as e:
            self.root.after(0, lambda: self._scan_error(str(e)))

    def _scan_complete(self, count, elapsed, regions, total_bytes):
        with self.data.lock:
            self.data.is_scanning = False
        self.progress_var.set(100)
        mb = total_bytes / (1024 * 1024)
        self.progress_label.config(text=f"✅ {mb:.1f} MB | {regions} рег. за {elapsed:.1f}с", foreground='#2e7d32')
        self.refresh_tree()

    def _scan_error(self, error):
        with self.data.lock:
            self.data.is_scanning = False
        self.progress_label.config(text=f"❌ Ошибка: {error}", foreground='#d32f2f')
        messagebox.showerror("Ошибка сканирования", error)

    def refresh_values(self):
        with self.data.lock:
            if not self.data.scan_results:
                return
        self.btn_refresh.config(state='disabled')
        self.progress_label.config(text="🔄 Обновление...", foreground='#f57c00')
        threading.Thread(target=self._do_refresh_values, daemon=True).start()

    def _do_refresh_values(self):
        changed = 0
        unchanged = 0
        errors = 0
        new_changed = set()
        current_values = {}

        with self.data.lock:
            scan_copy = copy.deepcopy(self.data.scan_results)
            pm = self.data.pm

        for addr, types in scan_copy.items():
            current_values[addr] = {}
            for type_key, baseline_val in types.items():
                t = SCAN_TYPES[type_key]
                try:
                    data = pm.read_bytes(addr, t['size'])
                    current_val = read_value(type_key, data, 0)
                    if current_val is not None:
                        current_values[addr][type_key] = current_val
                        if baseline_val is not None and current_val != baseline_val:
                            new_changed.add(addr)
                            changed += 1
                        else:
                            unchanged += 1
                    else:
                        errors += 1
                        current_values[addr][type_key] = baseline_val
                except:
                    errors += 1
                    current_values[addr][type_key] = baseline_val

        with self.data.lock:
            self.data.changed_addrs = new_changed
            self.data.push_history(f"Обновлено: изм. {changed}")

        self.root.after(0, lambda c=changed, u=unchanged, e=errors: self._refresh_complete(c, u, e, current_values))

    def _refresh_complete(self, changed, unchanged, errors, current_values):
        self.btn_refresh.config(state='normal')
        self.progress_label.config(text="✅ Обновлено", foreground='#2e7d32')
        old_results = self.data.scan_results
        with self.data.lock:
            self.data.scan_results = current_values
        self.refresh_tree()
        with self.data.lock:
            self.data.scan_results = old_results

    def next_scan_exact(self):
        search_value = self.search_var.get().strip()
        if not search_value:
            return
        with self.data.lock:
            if not self.data.scan_results:
                return
            scan_copy = copy.deepcopy(self.data.scan_results)
            selected_types = set(self.data.selected_types)
            pm = self.data.pm

        new_results = {}
        for addr, types in scan_copy.items():
            for type_key in selected_types:
                if type_key not in types:
                    continue
                t = SCAN_TYPES[type_key]
                parsed_value, err = parse_search_value(type_key, search_value)
                if err:
                    continue
                try:
                    if pm.read_bytes(addr, t['size']) == value_to_bytes(type_key, parsed_value):
                        val = read_value(type_key, pm.read_bytes(addr, t['size']), 0)
                        if val is not None:
                            if addr not in new_results:
                                new_results[addr] = {}
                            new_results[addr][type_key] = val
                except:
                    pass

        total = sum(len(t) for t in new_results.values())
        with self.data.lock:
            self.data.scan_results = new_results
            self.data.changed_addrs.clear()
            self.data.push_history(f"Точное '{search_value}' → {total}")
        self.refresh_tree()

    def filter_changed(self):
        with self.data.lock:
            if not self.data.scan_results:
                return
            scan_copy = copy.deepcopy(self.data.scan_results)
            pm = self.data.pm

        new_results = {}
        for addr, types in scan_copy.items():
            for type_key, baseline_val in types.items():
                t = SCAN_TYPES[type_key]
                try:
                    current_val = read_value(type_key, pm.read_bytes(addr, t['size']), 0)
                    if current_val is not None and baseline_val is not None and current_val != baseline_val:
                        if addr not in new_results:
                            new_results[addr] = {}
                        new_results[addr][type_key] = current_val
                except:
                    pass

        with self.data.lock:
            self.data.scan_results = new_results
            self.data.changed_addrs.clear()
            self.data.push_history(f"Фильтр: изменилось {sum(len(t) for t in new_results.values())}")
        self.refresh_tree()

    def filter_unchanged(self):
        with self.data.lock:
            if not self.data.scan_results:
                return
            scan_copy = copy.deepcopy(self.data.scan_results)
            pm = self.data.pm

        new_results = {}
        for addr, types in scan_copy.items():
            for type_key, baseline_val in types.items():
                t = SCAN_TYPES[type_key]
                try:
                    current_val = read_value(type_key, pm.read_bytes(addr, t['size']), 0)
                    if current_val is not None and baseline_val is not None and current_val == baseline_val:
                        if addr not in new_results:
                            new_results[addr] = {}
                        new_results[addr][type_key] = current_val
                except:
                    pass

        with self.data.lock:
            self.data.scan_results = new_results
            self.data.changed_addrs.clear()
            self.data.push_history(f"Фильтр: не изм. {sum(len(t) for t in new_results.values())}")
        self.refresh_tree()

    def go_back(self):
        desc = self.data.go_back()
        if desc:
            self.refresh_tree()
            self.update_history_buttons()

    def go_forward(self):
        desc = self.data.go_forward()
        if desc:
            self.refresh_tree()
            self.update_history_buttons()

    def update_history_buttons(self):
        self.btn_back.config(state='normal' if self.data.history_index > 0 else 'disabled')
        self.btn_forward.config(state='normal' if self.data.history_index < len(self.data.history) - 1 else 'disabled')
        self.history_label.config(text=f"📜 {self.data.history_index + 1}/{len(self.data.history)}")

    def reset_results(self):
        with self.data.lock:
            self.data.scan_results = {}
            self.data.scan_history = {}
            self.data.changed_addrs.clear()
            self.data.history.clear()
            self.data.history_index = -1
        self.refresh_tree()
        self.update_history_buttons()
        self.progress_var.set(0)
        self.progress_label.config(text="Готов", foreground='#2e7d32')

    def sort_tree(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            items.sort(key=lambda x: float(x[0]) if x[0].replace('.', '', 1).replace('-', '', 1).isdigit() else x[0])
        except:
            items.sort()
        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        total = 0
        with self.data.lock:
            scan_copy = copy.deepcopy(self.data.scan_results)
            hist_copy = copy.deepcopy(self.data.scan_history)
            changed_copy = set(self.data.changed_addrs)
            freeze_copy = dict(self.data.freeze_threads)
            pm = self.data.pm

        for addr in sorted(scan_copy.keys()):
            is_changed = addr in changed_copy
            for type_key in sorted(scan_copy[addr].keys()):
                val = scan_copy[addr][type_key]
                old_val = hist_copy.get(addr, {}).get(type_key)
                t = SCAN_TYPES[type_key]
                val_str = f"{val:.6f}" if t['py'] == 'float' else str(val)
                old_str = (f"{old_val:.6f}" if t['py'] == 'float' else str(old_val)) if old_val is not None else "—"

                try:
                    hex_str = pm.read_bytes(addr, t['size']).hex()
                except:
                    hex_str = "???"

                frozen = "❄️" if addr in freeze_copy and type_key in freeze_copy[addr] else ""
                tags = ['changed'] if is_changed else (['frozen_tag'] if frozen else ['normal'])

                self.tree.insert('', 'end', values=(f"0x{addr:X}", t['name'], val_str, old_str, hex_str, frozen),
                                 tags=tags)
                total += 1
        self.result_count.config(text=f"Адресов: {len(scan_copy)}, Записей: {total}")

    def write_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        addr = int(item['values'][0], 16)
        type_name = item['values'][1]
        old_val = item['values'][2]

        type_key = next((k for k, v in SCAN_TYPES.items() if v['name'] == type_name), None)
        if not type_key:
            return

        new_val = simpledialog.askstring("Запись", f"Новое значение для 0x{addr:X}:\nТекущее: {old_val}")
        if not new_val:
            return

        parsed, err = parse_search_value(type_key, new_val)
        if err:
            messagebox.showerror("Ошибка", err)
            return

        try:
            self.data.pm.write_bytes(addr, value_to_bytes(type_key, parsed), SCAN_TYPES[type_key]['size'])
            with self.data.lock:
                if addr in self.data.scan_results:
                    self.data.scan_results[addr][type_key] = parsed
            self.refresh_tree()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def freeze_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        addr = int(item['values'][0], 16)
        type_name = item['values'][1]
        old_val = item['values'][2]

        type_key = next((k for k, v in SCAN_TYPES.items() if v['name'] == type_name), None)
        if not type_key:
            return

        freeze_val = simpledialog.askstring("Заморозка",
                                            f"Значение для 0x{addr:X}:\n(пусто = текущее: {old_val})") or old_val

        parsed, err = parse_search_value(type_key, freeze_val)
        if err:
            messagebox.showerror("Ошибка", err)
            return

        with self.data.lock:
            if addr in self.data.freeze_threads and type_key in self.data.freeze_threads[addr]:
                self.data.freeze_threads[addr][type_key][1].set()
                del self.data.freeze_threads[addr][type_key]

        try:
            bytes_data = value_to_bytes(type_key, parsed)
            stop_event = threading.Event()

            def worker():
                while not stop_event.is_set():
                    try:
                        self.data.pm.write_bytes(addr, bytes_data, SCAN_TYPES[type_key]['size'])
                    except:
                        pass
                    time.sleep(0.1)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            with self.data.lock:
                if addr not in self.data.freeze_threads:
                    self.data.freeze_threads[addr] = {}
                self.data.freeze_threads[addr][type_key] = (thread, stop_event)
            self.refresh_tree()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def unfreeze_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        addr = int(item['values'][0], 16)
        type_name = item['values'][1]
        type_key = next((k for k, v in SCAN_TYPES.items() if v['name'] == type_name), None)

        with self.data.lock:
            if type_key and addr in self.data.freeze_threads and type_key in self.data.freeze_threads[addr]:
                self.data.freeze_threads[addr][type_key][1].set()
                del self.data.freeze_threads[addr][type_key]
                if not self.data.freeze_threads[addr]:
                    del self.data.freeze_threads[addr]
        self.refresh_tree()

    def copy_address(self):
        selection = self.tree.selection()
        if selection:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.tree.item(selection[0])['values'][0])


# ===== ЗАПУСК =====
if __name__ == '__main__':
    data_manager = ScannerDataManager()

    root = tk.Tk()
    app = MemoryScannerApp(root, data_manager, None)

    bot_manager = TelegramBotManager(data_manager)
    bot_manager.start()

    root.mainloop()
