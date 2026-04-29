#ifndef ENTROPY_H
#define ENTROPY_H

#include <vector>
#include <cstdint>
#include <cmath>
#include <cstddef>

/**
 * Энтропия Шеннона — мера информационной "случайности" данных.
 *
 * Формула: H = -Σ p(x) × log₂(p(x))
 *   где p(x) — вероятность встретить байт со значением x в потоке.
 *
 * Свойства:
 *   - Диапазон значений: от 0.0 до 8.0 (для байтового алфавита).
 *   - 0.0 — все байты одинаковые (например, файл из одних нулей).
 *   - 8.0 — равномерное распределение (идеально случайные данные).
 *
 * Применение в анализе бинарников:
 *   - Обычный машинный код:        энтропия 5.0 - 6.5
 *   - Текстовые данные ASCII:      энтропия 4.0 - 5.0
 *   - Сжатые/упакованные данные:   энтропия 7.0 - 7.99
 *   - Зашифрованные данные:        энтропия ≥ 7.5
 *
 * Если энтропия секции .text > 7.0 — почти наверняка упаковщик
 * (UPX, Themida, VMProtect) или зашифрованная полезная нагрузка.
 */
class Entropy {
public:
    /**
     * Вычисляет энтропию Шеннона для произвольного диапазона байтов.
     * @param data   Указатель на начало данных.
     * @param length Размер диапазона в байтах.
     * @return Значение энтропии в диапазоне [0.0, 8.0].
     *         Для пустого ввода возвращает 0.0.
     */
    static double calculate(const uint8_t* data, size_t length) {
        if (length == 0 || data == nullptr) {
            return 0.0;
        }

        // Шаг 1: подсчёт частот каждого из 256 возможных значений байта.
        // Используем uint64_t, чтобы гарантированно вместить количество
        // байтов в файлах размером в гигабайты.
        uint64_t frequency[256] = {0};
        for (size_t i = 0; i < length; ++i) {
            frequency[data[i]]++;
        }

        // Шаг 2: применение формулы Шеннона.
        // Преобразуем общую длину в double один раз — избегаем
        // дорогостоящих преобразований в цикле.
        const double total = static_cast<double>(length);
        double entropy = 0.0;

        for (int i = 0; i < 256; ++i) {
            if (frequency[i] == 0) {
                continue;  // 0 × log(0) = 0 по соглашению, пропускаем
            }
            const double p = static_cast<double>(frequency[i]) / total;
            entropy -= p * std::log2(p);
        }

        return entropy;
    }

    /**
     * Перегрузка для удобства работы с std::vector.
     */
    static double calculate(const std::vector<uint8_t>& data) {
        return calculate(data.data(), data.size());
    }
};

#endif // ENTROPY_H
