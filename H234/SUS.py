import scipy.stats as stats
import numpy as np

faba_sus = [
    57.5, 87.5, 65.0, 62.5, 85.0, 80.0, 62.5, 85.0, 
    55.0, 60.0, 75.0, 55.0, 72.5, 57.5, 55.0, 60.0, 
    77.5, 87.5, 92.5, 92.5, 100.0, 90.0, 85.0, 87.5, 
    85.0, 75.0, 87.5, 85.0, 75.0, 62.5
]

duo_sus = [
    77.5, 77.5, 62.5, 72.5, 85.0, 100.0, 72.5, 87.5, 
    72.5, 92.5, 90.0, 52.5, 82.5, 77.5, 82.5, 57.5, 
    60.0, 75.0, 82.5, 72.5, 57.5, 77.5, 65.0, 72.5, 
    65.0, 65.0, 55.0, 52.5, 65.0, 80.0
]

if len(faba_sus) != len(duo_sus):
    raise ValueError(f"Mismatch: FABA has {len(faba_sus)} items, DUO has {len(duo_sus)} items.")

differences = np.array(faba_sus) - np.array(duo_sus)

t_statistic, p_value_two_tailed = stats.ttest_rel(faba_sus, duo_sus)


p_value_one_tailed = p_value_two_tailed / 2
if t_statistic < 0:
    p_value_one_tailed = 1 - p_value_one_tailed

mean_diff = np.mean(differences)
std_diff = np.std(differences, ddof=1)
cohens_d = mean_diff / std_diff

print(f"Mean FABA: {np.mean(faba_sus):.2f}")
print(f"Mean DUO: {np.mean(duo_sus):.2f}")
print(f"t-statistic: {t_statistic:.3f}")
print(f"p-value (one-tailed, FABA > DUO): {p_value_one_tailed:.4f}")
print(f"p-value (two-tailed): {p_value_two_tailed:.4f}")
print(f"Cohen's d: {cohens_d:.3f}")
print(f"N: {len(faba_sus)}")