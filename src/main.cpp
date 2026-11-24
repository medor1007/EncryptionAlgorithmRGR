#include <iostream>
#include <limits>
#include <string>

namespace {

enum class Cipher {
    Hill,
    ElGamal,
};

int read_choice(int minimum, int maximum) {
    while (true) {
        std::cout << "Выберите пункт: ";
        std::string input;
        if (!std::getline(std::cin, input)) {
            return 0;
        }

        try {
            std::size_t parsed = 0;
            const int choice = std::stoi(input, &parsed);
            if (parsed == input.size() && choice >= minimum && choice <= maximum) {
                return choice;
            }
        } catch (const std::exception&) {
            // Invalid input is handled by the common message below.
        }

        std::cout << "Некорректный ввод. Введите число от " << minimum
                  << " до " << maximum << ".\n";
    }
}

void show_cipher_menu(Cipher cipher) {
    const std::string cipher_name =
        cipher == Cipher::Hill ? "шифр Хилла" : "шифр Эль-Гамаля";

    while (true) {
        std::cout << "\n=== " << cipher_name << " ===\n"
                  << "1. Зашифровать текст\n"
                  << "2. Расшифровать текст\n"
                  << "3. Зашифровать файл\n"
                  << "4. Расшифровать файл\n"
                  << "5. Сгенерировать ключи\n"
                  << "0. Назад\n";

        const int choice = read_choice(0, 5);
        if (choice == 0) {
            return;
        }

        std::cout << "Эта операция появится после подключения модуля шифра.\n";
    }
}

}  // namespace

int main() {
    while (true) {
        std::cout << "\n========================================\n"
                  << " Encryption Algorithm RGR\n"
                  << " Учебное шифрование и дешифрование\n"
                  << "========================================\n"
                  << "1. Шифр Хилла\n"
                  << "2. Шифр Эль-Гамаля\n"
                  << "0. Выход\n";

        const int choice = read_choice(0, 2);
        if (choice == 0) {
            std::cout << "До свидания!\n";
            return 0;
        }

        show_cipher_menu(choice == 1 ? Cipher::Hill : Cipher::ElGamal);
    }
}
