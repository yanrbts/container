import random

g_ftype = [
    "txt",
    "pdf",
    "png"
]

def random_filetype():
    # 指定每种文件类型的权重，分别对应 g_ftype 列表
    weights = [1, 4, 2]  # "txt" 占 1/5, "pdf" 和 "png" 各占 2/5
    return random.choices(g_ftype, weights=weights, k=1)[0]

# 测试函数
print([random_filetype() for _ in range(10)])
