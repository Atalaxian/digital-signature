import math
import random
import secrets
import sys
from typing import Optional
from typing import Tuple

from PyQt5 import QtCore, Qt
from PyQt5.QtWidgets import QWidget, QApplication, QFileDialog
from bitstring import BitArray

from error_window import Ui_widget
from main_window import Ui_Form


class MyThread(QtCore.QThread):
    mysignal = QtCore.pyqtSignal(str)
    mysignal_result = QtCore.pyqtSignal(str)
    md5 = None

    def __init__(self, md5) -> None:
        QtCore.QThread.__init__(self, parent=None)
        self.md5 = md5

    def run(self):
        result = self.md5.calc_hash_from_file(signal=self.mysignal)
        self.mysignal_result.emit(result)


class MyException(Exception):
    text = None

    def __init__(self, text) -> None:
        super().__init__()
        self.text = text


def gcd_extended(a, b) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


class MD5:
    file = None
    T = None
    log = []
    A_start = BitArray('0x67452301')
    B_start = BitArray('0xefcdab89')
    C_start = BitArray('0x98badcfe')
    D_start = BitArray('0x10325476')
    s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    def __init__(self, file) -> None:
        self.file = file
        self.T = self.calc_t()

    @staticmethod
    def bit_and(str_1: str, str_2: str) -> Optional[str]:
        result_str = ''
        if len(str_1) != len(str_2):
            return None
        mylist = [(int(str_1[x]), int(str_2[x])) for x in range(len(str_1))]
        for elem in mylist:
            x, y = elem
            if x == 1 and y == 1:
                result_str += '1'
            else:
                result_str += '0'
        return result_str

    @staticmethod
    def bit_xor(str_1: str, str_2: str) -> Optional[str]:
        result_str = ''
        if len(str_1) != len(str_2):
            return None
        mylist = [(int(str_1[x]), int(str_2[x])) for x in range(len(str_1))]
        for elem in mylist:
            x, y = elem
            if (x + y) % 2 == 1:
                result_str += '1'
            else:
                result_str += '0'
        return result_str

    @staticmethod
    def bit_not(str_1: str) -> Optional[str]:
        result_str = ''
        for elem in str_1:
            if int(elem) == 1:
                result_str += '0'
            else:
                result_str += '1'
        return result_str

    @staticmethod
    def bit_left_shift(str_1: str, shift: int) -> Optional[str]:
        if shift < 0:
            return None
        mylist = list(str_1)
        for x in range(shift):
            mylist.pop(0)
            mylist.append('0')
        result = ''.join(mylist)
        return result

    @staticmethod
    def bit_or(str_1, str_2):
        result_str = ''
        if len(str_1) != len(str_2):
            return None
        mylist = [(int(str_1[x]), int(str_2[x])) for x in range(len(str_1))]
        for elem in mylist:
            x, y = elem
            if x == 1 or y == 1:
                result_str += '1'
            else:
                result_str += '0'
        return result_str

    @staticmethod
    def left_rotate(x, amount):
        x &= 0xFFFFFFFF
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    def calc_hash_from_file(self, signal=None):
        log = None
        if signal is None:
            log = list()
        bit_array = BitArray(filename=self.file)
        start_len = bit_array.len
        if signal is None:
            log.append(f'Начальная длина битового массива: {start_len}')
        else:
            signal.emit(f'Начальная длина битового массива: {start_len}')
        bit_array.append('0b1')
        division = math.floor(bit_array.len / 512)
        if division == 0:
            N = 0
        else:
            if (512 * division + 448) > bit_array.len:
                N = division
            else:
                N = division + 1
        if signal is None:
            log.append(f'Параметр N = {N}')
        else:
            signal.emit(f'Параметр N = {N}')
        new_len = 512 * N + 448
        num_add = new_len - bit_array.len
        if num_add == 0:
            N += 1
            num_add = 512
        start_str = '0b'
        for x in range(num_add):
            start_str += '0'
        bit_array.append(start_str)
        if signal is None:
            log.append('1. Выравнивание потока завершено.')
            log.append(f'Новая длина потока L(`) = {bit_array.len}')
            log.append(f'(448%512) = {448 % 512}. ({bit_array.len}%512) = {bit_array.len % 512}')
        else:
            signal.emit('1. Выравнивание потока завершено.')
            signal.emit(f'Новая длина потока L(`) = {bit_array.len}')
            signal.emit(f'(448%512) = {448 % 512}. ({bit_array.len}%512) = {bit_array.len % 512}')
        bit_array.append(start_len.to_bytes(8, byteorder='little'))
        if signal is None:
            log.append('2. Добавление длины сообщения завершено.')
            log.append(f'Новая длина потока L(`) = {bit_array.len}. ({bit_array.len}%512) = {bit_array.len % 512}')
            log.append(f'Все необходимо обработать {int(bit_array.len / 512)} блоков')
        else:
            signal.emit('2. Добавление длины сообщения завершено.')
            signal.emit(f'Новая длина потока L(`) = {bit_array.len}. ({bit_array.len}%512) = {bit_array.len % 512}')
            signal.emit(f'Все необходимо обработать {int(bit_array.len / 512)} блоков')
        blocks = [bit_array[x * 512: (x + 1) * 512] for x in range(int(bit_array.len / 512))]
        if signal is None:
            log.append('Начат выполнение операций')
        else:
            signal.emit('Начат выполнение операций')
        for z, elem in enumerate(blocks):
            if signal is None:
                log.append(f'Блок №{z + 1}')
            else:
                signal.emit(f'Блок №{z + 1}')
            chunk = [elem[x * 32: (x + 1) * 32] for x in range(16)]
            A = self.A_start
            B = self.B_start
            C = self.C_start
            D = self.D_start
            F, g = (None, None)
            for x in range(64):
                if 15 >= x >= 0:
                    # Протестировано. Вроде работает.
                    F = self.bit_or((self.bit_and(B.bin, C.bin)), self.bit_and(self.bit_not(B.bin), D.bin))
                    g = x
                if 31 >= x >= 16:
                    F = self.bit_or(self.bit_and(D.bin, B.bin), self.bit_and(self.bit_not(D.bin), C.bin))
                    g = (5 * x + 1) % 16
                if 47 >= x >= 32:
                    F = self.bit_xor(self.bit_xor(B.bin, C.bin), D.bin)
                    g = (3 * x + 5) % 16
                if 64 >= x >= 48:
                    F = self.bit_xor(C.bin, self.bit_or(B, self.bit_not(D.bin)))
                    g = (7 * x) % 16
                F = (int(BitArray('0b' + F).bin, 2) + int(A.bin, 2)) + \
                    (int(self.T[x].bin, 2) + int.from_bytes(chunk[g].bytes, byteorder='little'))
                A = D
                D = C
                C = B
                B = (int(B.bin, 2) + self.left_rotate(F, self.s[x])) & 0xFFFFFFFF
                B = BitArray(B.to_bytes(length=4, byteorder='big'))
                if z == 0:
                    if signal is None:
                        log.append(f'[x = {x}] A = {A} B = {B} C = {C} D = {D}')
                    else:
                        signal.emit(f'[x = {x}] A = {A} B = {B} C = {C} D = {D}')
            if z < len(blocks) - 1:
                order = 'big'
            else:
                order = 'little'
            self.A_start = BitArray(((int(self.A_start.bin, 2) +
                                      int(A.bin, 2)) & 0xFFFFFFFF).to_bytes(length=4, byteorder=order))
            self.B_start = BitArray(((int(self.B_start.bin, 2) +
                                      int(B.bin, 2)) & 0xFFFFFFFF).to_bytes(length=4, byteorder=order))
            self.C_start = BitArray(((int(self.C_start.bin, 2) +
                                      int(C.bin, 2)) & 0xFFFFFFFF).to_bytes(length=4, byteorder=order))
            self.D_start = BitArray(((int(self.D_start.bin, 2) +
                                      int(D.bin, 2)) & 0xFFFFFFFF).to_bytes(length=4, byteorder=order))
        result = ''.join([str(self.A_start.hex),
                          str(self.B_start.hex),
                          str(self.C_start.hex),
                          str(self.D_start.hex)])
        if signal is None:
            log.append(f'Итоговый хэш: {result}')
        else:
            signal.emit(f'Итоговый хэш: {result}')
        if log is not None:
            return result, log
        else:
            return result

    @staticmethod
    def calc_t():
        T = list()
        for x in range(1, 65):
            mybits = hex(int(pow(2, 32) * abs(math.sin(x))))
            T.append(BitArray(mybits))
        return T


class RSA:
    text = None
    number = None
    start_prime_number = None
    open_key = None
    close_key = None

    def __init__(self, value, open_key=None, close_key=None, start_prime_number=1000) -> None:
        if isinstance(value, str) or isinstance(value, list):
            self.text = value
        elif isinstance(value, int):
            self.number = value
        self.open_key = open_key
        self.close_key = close_key
        self.start_prime_number = start_prime_number

    def get_prime_numbers(self, start=0, number=2):
        list_prime_number = list()
        while len(list_prime_number) != number:
            if self.is_prime(start):
                list_prime_number.append(start)
                start += 1
        return list_prime_number

    def encode_rsa(self, code_key='e'):
        try:
            prime_numbers = self.get_prime_number(self.start_prime_number)
        except OverflowError:
            start_value = int(math.sqrt(self.start_prime_number)) + 1
            prime_numbers = self.get_prime_numbers(start=start_value, number=2)
        p = secrets.choice(prime_numbers)
        prime_numbers.remove(p)
        q = secrets.choice(prime_numbers)
        n = p * q
        eyler = (p - 1) * (q - 1)
        list_e = list()
        for x in range(2, eyler + 1):
            if self.is_prime(x):
                gcd, xe, y = gcd_extended(x, eyler)
                if gcd == 1:
                    list_e.append(x)
                    if len(list_e) == 30:
                        break
        e = 0
        d = 0
        list_e = list(reversed(list_e))
        random.shuffle(list_e)
        for elem in list_e:
            gcd, x, y = gcd_extended(elem, eyler)
            if gcd == 1 and x > 0:
                d = x
                e = elem
                break
        self.open_key = (e, n)
        self.close_key = (d, n)
        encode_text = ''
        if self.number is not None:
            if code_key == 'e':
                code = pow(self.number, e, n)
            elif code_key == 'd':
                code = pow(self.number, d, n)
            else:
                raise MyException(f'Ошибка. Допустимые коды: e, d')
            return code
        elif self.text is not None:
            for x, elem in enumerate(self.text):
                if x != 0:
                    encode_text += ','
                intelem = ord(elem)
                if code_key == 'e':
                    code_int = pow(intelem, e, n)
                elif code_key == 'd':
                    code_int = pow(intelem, d, n)
                else:
                    raise MyException(f'Ошибка. Допустимые коды: e, d')
                encode_text += str(code_int)
            return encode_text

    def decode_rsa(self, code_key='d'):
        if code_key == 'd':
            self.close_key = self.close_key.replace('{', '')
            self.close_key = self.close_key.replace('}', '')
            self.close_key = self.close_key.replace('(', '')
            self.close_key = self.close_key.replace(')', '')
            keys = self.close_key.split(',')
            d, n = [int(x) for x in keys]
            decode_text = ''
            if self.text is not None:
                for elem in self.text:
                    mod = pow(int(elem), d, n)
                    code_char = chr(mod)
                    decode_text += str(code_char)
                return decode_text
            elif self.number is not None:
                mod = pow(self.number, d, n)
                return mod
        elif code_key == 'e':
            self.open_key = self.open_key.replace('{', '')
            self.open_key = self.open_key.replace('}', '')
            self.open_key = self.open_key.replace('(', '')
            self.open_key = self.open_key.replace(')', '')
            keys = self.open_key.split(',')
            e, n = [int(x) for x in keys]
            if self.text is not None:
                decode_text = ''
                for elem in self.text:
                    mod = pow(int(elem), e, n)
                    try:
                        code_char = chr(mod)
                    except ValueError:
                        code_char = '`'
                    decode_text += str(code_char)
                return decode_text
            elif self.number is not None:
                mod = pow(self.number, e, n)
                return mod

    @staticmethod
    def get_prime_number(n, search_segment=1000) -> list:
        a = range(n + search_segment + 1)
        a = list(a)
        a[1] = 0
        prev_result_list = []
        i = 2
        while i <= (n + search_segment):
            if a[i] != 0:
                prev_result_list.append(a[i])
                for j in range(i, n + search_segment + 1, i):
                    a[j] = 0
            i += 1
        result_list = [x for x in prev_result_list if x >= n]
        return result_list

    @staticmethod
    def is_prime(number) -> bool:
        n = number
        counter = 0
        for i in range(1, n + 1):
            if n % i == 0:
                counter += 1
        return True if counter == 2 else False

    def get_open_key(self) -> tuple:
        return self.open_key

    def get_close_key(self) -> tuple:
        return self.close_key


class ErrorWindow(QWidget, Ui_widget):
    def __init__(self, text) -> None:
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('Ошибка')
        self.setWindowModality(Qt.Qt.ApplicationModal)
        self.error_label.setText(text)


class MainWindow(QWidget, Ui_Form):
    start_file_path = None
    end_file_path = None
    error_window = None
    thread = None

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('Лабораторная работа №4. Создание цифровой подписи.')
        self.start_choice_file_ui.clicked.connect(self.set_start_file)
        self.end_choice_file_ui.clicked.connect(self.set_end_file)
        self.start_save_log_ui.clicked.connect(self.save_start_log)
        self.end_save_log_ui.clicked.connect(self.save_end_log)
        self.start_create_digiral_signature_ui.clicked.connect(self.create_signature)
        self.proof_signature_ui.clicked.connect(self.proof_signature)
        self.min_count.setText('1000')

    @QtCore.pyqtSlot()
    def create_signature(self):
        self.start_log_ui.clear()
        self.start_digital_key_ui.clear()
        if self.start_file_path is None:
            self.error_window = ErrorWindow('Отсутствует путь к необходимому файлу.')
            self.error_window.show()
            return
        md5_hash = MD5(self.start_file_path)
        self.thread = MyThread(md5_hash)
        self.thread.mysignal.connect(self.append_logs_1, QtCore.Qt.QueuedConnection)
        self.thread.mysignal_result.connect(self.result_md5_1, QtCore.Qt.QueuedConnection)
        self.thread.finished.connect(self.finish_thread, QtCore.Qt.QueuedConnection)
        self.thread.start()

    @QtCore.pyqtSlot(str)
    def append_logs_1(self, log):
        self.start_log_ui.append(log)

    @QtCore.pyqtSlot(str)
    def append_logs_2(self, log):
        self.end_log_ui.append(log)

    @QtCore.pyqtSlot(str)
    def result_md5_1(self, result):
        rsa = RSA(value=result, start_prime_number=int(self.min_count.text()))
        cipher = rsa.encode_rsa(code_key='d')
        self.start_digital_key_ui.append(str(cipher))
        open_key = rsa.get_open_key()
        close_key = rsa.get_close_key()
        self.start_open_key_ui.setText(str(open_key))
        self.start_closed_key_ui.setText(str(close_key))

    @QtCore.pyqtSlot(str)
    def result_md5_2(self, result):
        try:
            start_value = list(map(int, self.end_digital_key_ui.toPlainText().split(',')))
        except ValueError:
            self.error_window = ErrorWindow('Электронная подпись отсутствует или задана в неверном формате.')
            self.error_window.show()
            return
        rsa = RSA(value=start_value, open_key=self.end_open_key_ui.text())
        try:
            decode_hash = rsa.decode_rsa(code_key='e')
        except ValueError:
            self.error_window = ErrorWindow('Открытый ключ отсутсвует или задан в неверном формате.')
            self.error_window.show()
            return
        self.end_log_ui.append(f'Расшифрованный хэш: {decode_hash}')
        if result == decode_hash:
            self.end_log_ui.append('Подпись подтверждена')
        else:
            self.end_log_ui.append('Подпись не подтверждена')

    @QtCore.pyqtSlot()
    def proof_signature(self):
        self.end_log_ui.clear()
        if self.end_file_path is None:
            self.error_window = ErrorWindow('Отсутствует путь к необходимому файлу.')
            self.error_window.show()
            return
        md5_hash = MD5(self.end_file_path)
        self.thread = MyThread(md5_hash)
        self.thread.mysignal.connect(self.append_logs_2, QtCore.Qt.QueuedConnection)
        self.thread.mysignal_result.connect(self.result_md5_2, QtCore.Qt.QueuedConnection)
        self.thread.finished.connect(self.finish_thread, QtCore.Qt.QueuedConnection)
        self.thread.start()

    @QtCore.pyqtSlot()
    def finish_thread(self):
        del self.thread

    @QtCore.pyqtSlot()
    def set_start_file(self) -> None:
        filegialog = QFileDialog.getOpenFileUrl(self, 'Выбор файла',
                                                filter=str("Все файлы (*.*)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            self.start_file_path = file_path
            self.start_path_file_ui.setText(file_path)

    @QtCore.pyqtSlot()
    def set_end_file(self) -> None:
        filegialog = QFileDialog.getOpenFileUrl(self, 'Выбор файла',
                                                filter=str("Все файды (*.*)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            self.end_file_path = file_path
            self.end_file_path_ui.setText(file_path)

    @QtCore.pyqtSlot()
    def save_start_log(self) -> None:
        text = self.start_log_ui.toPlainText()
        if len(text) == 0:
            self.error_window = ErrorWindow('Нет логов')
            self.error_window.show()
            return
        filegialog = QFileDialog.getSaveFileUrl(self, 'Сохранение',
                                                filter=str("Текстовый файл (*.txt)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            file = open(file_path, 'w', encoding='UTF-8')
            file.write(text)

    @QtCore.pyqtSlot()
    def save_end_log(self) -> None:
        text = self.end_log_ui.toPlainText()
        if len(text) == 0:
            self.error_window = ErrorWindow('Нет логов')
            self.error_window.show()
            return
        filegialog = QFileDialog.getSaveFileUrl(self, 'Сохранение',
                                                filter=str("Текстовый файл (*.txt)"))
        if filegialog[0]:
            file_path = filegialog[0].toLocalFile()
            if file_path == '':
                return
            file = open(file_path, 'w', encoding='UTF-8')
            file.write(text)


if __name__ == '__main__':
    qapp = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(qapp.exec())
