import scipy.stats as stats
import numpy as np

faba_security = [4, 5, 5, 5, 4, 3, 5, 5, 4, 3, 4, 5, 4, 5, 4, 5, 4, 4, 5, 5, 5, 5, 5, 5, 4, 4, 5, 5, 4, 4]

duo_security = [5, 2, 4, 4, 5, 4, 4, 4, 4, 4, 4, 4, 4, 5, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]

print(f"FABA participants: {len(faba_security)}")
print(f"DUO participants: {len(duo_security)}")

mean_faba = np.mean(faba_security)
mean_duo = np.mean(duo_security)

print(f"\nMean FABA Security: {mean_faba:.2f}")
print(f"Mean DUO Security: {mean_duo:.2f}")
print(f"Difference (FABA - DUO): {mean_faba - mean_duo:.2f}")

differences = np.array(faba_security) - np.array(duo_security)
t_statistic, p_value_two_tailed = stats.ttest_rel(faba_security, duo_security)

if t_statistic > 0:
    p_value_one_tailed = p_value_two_tailed / 2
else:
    p_value_one_tailed = 1 - (p_value_two_tailed / 2)

mean_diff = np.mean(differences)
std_diff = np.std(differences, ddof=1)
cohens_d = mean_diff / std_diff

print(f"\nt-statistic: {t_statistic:.3f}")
print(f"p-value (two-tailed): {p_value_two_tailed:.4f}")
print(f"p-value (one-tailed, FABA ≥ DUO): {p_value_one_tailed:.4f}")
print(f"Cohen's d: {cohens_d:.3f}")
print(f"Degrees of freedom: {len(faba_security) - 1}")

percentage_diff = ((mean_faba - mean_duo) / mean_duo) * 100
print(f"\nPercentage difference: {percentage_diff:.1f}%")