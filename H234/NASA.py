import scipy.stats as stats
import numpy as np


faba_tlx = [
    2.50, 3.67, 6.33, 5.67, 2.17, 5.00, 5.50, 1.50, 
    5.83, 6.67, 5.50, 6.83, 2.83, 3.33, 4.17, 5.00, 
    5.00, 5.00, 2.17, 2.00, 1.83, 2.67, 2.67, 2.33, 
    3.00, 3.17, 2.00, 2.50, 4.17, 5.33
]

duo_tlx = [
    1.33, 5.83, 5.00, 4.67, 2.00, 1.00, 5.67, 2.33, 
    3.33, 0.83, 2.50, 5.67, 2.50, 1.50, 1.50, 5.00, 
    5.33, 4.83, 5.33, 5.00, 6.83, 4.17, 4.83, 4.00, 
    4.33, 4.50, 4.50, 4.17, 5.17, 2.17
]
print(f"FABA participants: {len(faba_tlx)}")
print(f"DUO participants: {len(duo_tlx)}")

mean_faba = np.mean(faba_tlx)
mean_duo = np.mean(duo_tlx)

print(f"\nMean FABA TLX: {mean_faba:.2f}")
print(f"Mean DUO TLX: {mean_duo:.2f}")
print(f"Difference (FABA - DUO): {mean_faba - mean_duo:.2f}")


differences = np.array(faba_tlx) - np.array(duo_tlx)
t_statistic, p_value_two_tailed = stats.ttest_rel(faba_tlx, duo_tlx)


if t_statistic > 0: 
    p_value_one_tailed = p_value_two_tailed / 2
else:
    p_value_one_tailed = 1 - (p_value_two_tailed / 2)


mean_diff = np.mean(differences)
std_diff = np.std(differences, ddof=1)
cohens_d = mean_diff / std_diff

print(f"\nt-statistic: {t_statistic:.3f}")
print(f"p-value (one-tailed, FABA ≤ DUO): {p_value_one_tailed:.4f}")
print(f"p-value (two-tailed): {p_value_two_tailed:.4f}")
print(f"Cohen's d: {cohens_d:.3f}")
print(f"Degrees of freedom: {len(faba_tlx) - 1}")

percentage_increase = ((mean_faba - mean_duo) / mean_duo) * 100
print(f"\nPercentage increase: {percentage_increase:.1f}%")