SRC_DIR = src
BUILD_DIR = build

C_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(C_FILES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all : $(BUILD_DIR)/networking.elf

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/networking.elf: $(OBJ_FILES) | $(BUILD_DIR)
	gcc -o $(BUILD_DIR)/networking.elf $(OBJ_FILES)

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c | $(BUILD_DIR)
	gcc -c $< -o $@ -MMD

-include $(OBJ_FILES:.o=.d)

clean :
	rm -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(BUILD_DIR)/networking.elf