from scipy.stats import wilcoxon

sr_faba = [0,0,0.67,1,0,0,1,1,0,0.33,1,1,0.67,0.33,0.33,0.67,1,1,1,1,1,0.67]
sr_duo = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]

stat, p = wilcoxon(sr_faba, sr_duo, alternative='two-sided')
print(p)

print(len(sr_faba))
print(len(sr_duo))

