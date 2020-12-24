################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include Drivers/STM32L0xx_HAL_Driver/Src/subdir.mk
-include Core/Startup/subdir.mk
-include Core/Src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 
EXECUTABLES += \
BME_IoT_Node.elf \

SIZE_OUTPUT += \
default.size.stdout \

OBJDUMP_LIST += \
BME_IoT_Node.list \

OBJCOPY_BIN += \
BME_IoT_Node.bin \


# All Target
all: BME_IoT_Node.elf secondary-outputs

# Tool invocations
BME_IoT_Node.elf: $(OBJS) $(USER_OBJS) X:\STM32\Project\Workspace\BME_IoT_Node\STM32L011K4TX_FLASH.ld
	arm-none-eabi-gcc -o "BME_IoT_Node.elf" @"objects.list" $(USER_OBJS) $(LIBS) -mcpu=cortex-m0plus -T"X:\STM32\Project\Workspace\BME_IoT_Node\STM32L011K4TX_FLASH.ld" --specs=nosys.specs -Wl,-Map="BME_IoT_Node.map" -Wl,--gc-sections -static --specs=nano.specs -mfloat-abi=soft -mthumb -Wl,--start-group -lc -lm -Wl,--end-group
	@echo 'Finished building target: $@'
	@echo ' '

default.size.stdout: $(EXECUTABLES)
	arm-none-eabi-size  $(EXECUTABLES)
	@echo 'Finished building: $@'
	@echo ' '

BME_IoT_Node.list: $(EXECUTABLES)
	arm-none-eabi-objdump -h -S $(EXECUTABLES) > "BME_IoT_Node.list"
	@echo 'Finished building: $@'
	@echo ' '

BME_IoT_Node.bin: $(EXECUTABLES)
	arm-none-eabi-objcopy  -O binary $(EXECUTABLES) "BME_IoT_Node.bin"
	@echo 'Finished building: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) *
	-@echo ' '

secondary-outputs: $(SIZE_OUTPUT) $(OBJDUMP_LIST) $(OBJCOPY_BIN)

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
