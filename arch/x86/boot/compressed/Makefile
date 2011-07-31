#
# linux/arch/x86/boot/compressed/Makefile
#
# create a compressed vmlinux image from the original vmlinux
#

targets := vmlinux.lds vmlinux vmlinux.bin vmlinux.bin.gz vmlinux.bin.bz2 vmlinux.bin.lzma vmlinux.bin.xz vmlinux.bin.lzo head_$(BITS).o misc.o string.o cmdline.o early_serial_console.o piggy.o

KBUILD_CFLAGS := -m$(BITS) -D__KERNEL__ $(LINUX_INCLUDE) -O2
KBUILD_CFLAGS += -fno-strict-aliasing -fPIC
KBUILD_CFLAGS += -DDISABLE_BRANCH_PROFILING
cflags-$(CONFIG_X86_32) := -march=i386
cflags-$(CONFIG_X86_64) := -mcmodel=small
KBUILD_CFLAGS += $(cflags-y)
KBUILD_CFLAGS += $(call cc-option,-ffreestanding)
KBUILD_CFLAGS += $(call cc-option,-fno-stack-protector)

KBUILD_AFLAGS  := $(KBUILD_CFLAGS) -D__ASSEMBLY__
GCOV_PROFILE := n

LDFLAGS := -m elf_$(UTS_MACHINE)
LDFLAGS_vmlinux := -T

hostprogs-y	:= mkpiggy

	# $(obj)即当前文件所在的目录
	# 解决完各个依赖后
	# 使用连接脚本将各个文件连接成含有经过压缩的顶层Makefile中的目标vmlinux的压缩映像
	# 压缩映像vmlinux头部连接的misc.o中含有解压代码

	# 例如: ld -m elf_i386   -T arch/x86/boot/compressed/vmlinux.lds
	#         arch/x86/boot/compressed/head_32.o arch/x86/boot/compressed/misc.o
	#         arch/x86/boot/compressed/string.o arch/x86/boot/compressed/cmdline.o
	#         arch/x86/boot/compressed/early_serial_console.o arch/x86/boot/compressed/piggy.o
	#         -o arch/x86/boot/compressed/vmlinux

$(obj)/vmlinux: $(obj)/vmlinux.lds $(obj)/head_$(BITS).o $(obj)/misc.o $(obj)/string.o $(obj)/cmdline.o $(obj)/early_serial_console.o $(obj)/piggy.o FORCE
	$(call if_changed,ld)
	@:

	# 使用objcopy得到2进制文件vmlinux.bin
	# 例如: objcopy  -R .comment -S vmlinux arch/x86/boot/compressed/vmlinux.bin
	# -R .comment 复制时去掉.comment节
	# -S strip

OBJCOPYFLAGS_vmlinux.bin :=  -R .comment -S
$(obj)/vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)


targets += vmlinux.bin.all vmlinux.relocs relocs
hostprogs-$(CONFIG_X86_NEED_RELOCS) += relocs

quiet_cmd_relocs = RELOCS  $@
      cmd_relocs = $(obj)/relocs $< > $@;$(obj)/relocs --abs-relocs $<
$(obj)/vmlinux.relocs: vmlinux $(obj)/relocs FORCE
	$(call if_changed,relocs)

vmlinux.bin.all-y := $(obj)/vmlinux.bin
vmlinux.bin.all-$(CONFIG_X86_NEED_RELOCS) += $(obj)/vmlinux.relocs

	# 使用gzip程序压缩vmlinux.bin和vmlinux.relocs
	# (cat arch/x86/boot/compressed/vmlinux.bin arch/x86/boot/compressed/vmlinux.relocs
	#         | gzip -n -f -9 > arch/x86/boot/compressed/vmlinux.bin.gz)
	#     || (rm -f arch/x86/boot/compressed/vmlinux.bin.gz ; false)
	# cmd_gzip : 压缩命令，定义在scripts/Makefile.lib内
	#                            scripts/Makefile.lib被包含在scripts/Makefile.build内

$(obj)/vmlinux.bin.gz: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,gzip)
$(obj)/vmlinux.bin.bz2: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,bzip2)
$(obj)/vmlinux.bin.lzma: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,lzma)
$(obj)/vmlinux.bin.xz: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,xzkern)
$(obj)/vmlinux.bin.lzo: $(vmlinux.bin.all-y) FORCE
	$(call if_changed,lzo)

	# 根据.config配置文件中的CONFIG_KERNEL_GZIP=y为suffix-y赋值为gz

suffix-$(CONFIG_KERNEL_GZIP)	:= gz
suffix-$(CONFIG_KERNEL_BZIP2)	:= bz2
suffix-$(CONFIG_KERNEL_LZMA)	:= lzma
suffix-$(CONFIG_KERNEL_XZ)	:= xz
suffix-$(CONFIG_KERNEL_LZO) 	:= lzo

	# 生成piggy.S的命令
	# 中间的或在生成失败的时候才执行删除动作

quiet_cmd_mkpiggy = MKPIGGY $@
      cmd_mkpiggy = $(obj)/mkpiggy $< > $@ || ( rm -f $@ ; false )

	# 先由arch/x86/boot/compressed/mkpiggy.c编译出小程序mkpiggy
	# 解决完依赖后，由mkpiggy小程序生成piggy.S
	# 例如: arch/x86/boot/compressed/mkpiggy
	#           arch/x86/boot/compressed/vmlinux.bin.gz > arch/x86/boot/compressed/piggy.S
	#           || ( rm -f arch/x86/boot/compressed/piggy.S ; false )

targets += piggy.S
$(obj)/piggy.S: $(obj)/vmlinux.bin.$(suffix-y) $(obj)/mkpiggy FORCE
	$(call if_changed,mkpiggy)
