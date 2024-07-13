# **************************************************************************** #
#                                   PROGRAM                                    #
# **************************************************************************** #

NAME = $(BUILD_DIR)/ft_nmap

# **************************************************************************** #
#                                     VARS                                     #
# **************************************************************************** #

UNAME_S := $(shell uname -s)

MAKE = make

CP = cp
MV = mv
MKDIR = mkdir -p
RM = rm -rf

# **************************************************************************** #
#                                   COMPILER                                   #
# **************************************************************************** #

CC = gcc
CPPFLAGS = -MMD
# CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow -Wconversion
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow

# **************************************************************************** #
#                                   SOURCES                                    #
# **************************************************************************** #

BUILD_DIR := build
SRC_DIR := srcs
INC_DIR := includes
LIB_DIR := lib

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:%.o=%.d)

# **************************************************************************** #
#                                    FLAGS                                     #
# **************************************************************************** #

CFLAGS += -I./$(INC_DIR)

# **************************************************************************** #
#                                     LIBS                                     #
# **************************************************************************** #

LFT_NAME = libft.a
LFT_DIR = $(LIB_DIR)/libft
LFT = $(LFT_DIR)/$(LFT_NAME)

LTPOOL_NAME = lib_tpool.a
LTPOOL_DIR = $(LIB_DIR)/lib_thread_pool
LTPOOL = $(LTPOOL_DIR)/$(LTPOOL_NAME)

CFLAGS += -I./$(LFT_DIR)/includes -I./$(LTPOOL_DIR)/include

LDFLAGS += -L./$(LFT_DIR) -lft -L./$(LTPOOL_DIR) -l_tpool

LDLIBS = $(LFT) $(LTPOOL)

# **************************************************************************** #
#                                    RULES                                     #
# **************************************************************************** #

all: $(NAME)

$(NAME): $(LDLIBS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

ifeq ($(UNAME_S),Linux)
sanitize:: CFLAGS += -g3 -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=bounds -fsanitize=null
endif
ifeq ($(UNAME_S),Darwin)
sanitize:: CFLAGS += -g3 -fsanitize=address
endif
sanitize:: $(NAME)

thread:: CFLAGS += -g3 -fsanitize=thread
thread:: $(NAME)

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(LFT):
	$(MAKE) -C $(LFT_DIR)

$(LTPOOL):
	$(MAKE) -C $(LTPOOL_DIR)

clean:
	$(MAKE) fclean -C $(LFT_DIR)
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(BUILD_DIR)

re:: clean
re:: all

-include $(DEPS)

.PHONY: all sanitize thread clean fclean re
