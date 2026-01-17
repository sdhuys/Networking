SRC_DIR = src
BUILD_DIR = build

C_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(C_FILES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all : networking.elf

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

networking.elf: $(OBJ_FILES)
	gcc -o networking.elf $(OBJ_FILES)

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c | $(BUILD_DIR)
	gcc -c $< -o $@ -MMD

-include $(OBJ_FILES:.o=.d)

clean :
	rm -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d networking.elf