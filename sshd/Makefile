# 定义目标文件
TARGET = sshc
# 定义源代码文件
SRCS = sshc.c
# 定义编译器
CC = gcc
# 定义链接选项
LIBS = -lssh -lutil

# 默认目标
all: $(TARGET)

# 链接生成目标文件
$(TARGET): $(SRCS)
	$(CC) $(SRCS) -o $(TARGET) $(LIBS)

# 清理生成的文件
clean:
	rm -f $(TARGET)
