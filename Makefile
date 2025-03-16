NAME = $(BUILD_DIR)/ft_nmap

MKDIR = mkdir -p
RM = rm -rf

CC = gcc
CPPFLAGS = -MMD
CFLAGS = -Wall -Wextra -Werror
LDFLAGS = -pthread

BUILD_DIR := build
SRC_DIR := srcs
INC_DIR := includes
LIB_DIR := lib

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:%.o=%.d)

CFLAGS += -I ./$(INC_DIR)

LFT_NAME = libft.a
LFT_DIR = $(LIB_DIR)/libft
LFT = $(LFT_DIR)/$(LFT_NAME)

CFLAGS += -I ./$(LFT_DIR)/includes

LDFLAGS += -L./$(LFT_DIR) -lft

LDLIBS = $(LFT)

all: $(NAME)

$(NAME): $(LDLIBS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

sanitize:: CFLAGS += -g3 -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=bounds -fsanitize=null
sanitize:: fclean $(NAME)

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(LFT):
	$(MAKE) -C $(LFT_DIR)

clean:
	$(MAKE) fclean -C $(LFT_DIR)
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(BUILD_DIR)

re: clean all

-include $(DEPS)

.PHONY: all sanitize clean fclean re
