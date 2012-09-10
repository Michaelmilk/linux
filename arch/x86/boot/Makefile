#
# arch/x86/boot/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1994 by Linus Torvalds
# Changed by many, many contributors over the years.
#

# If you want to preset the SVGA mode, uncomment the next line and
# set SVGA_MODE to whatever number you want.
# Set it to -DSVGA_MODE=NORMAL_VGA if you just want the EGA/VGA mode.
# The number is the same as you would ordinarily press at bootup.

SVGA_MODE	:= -DSVGA_MODE=NORMAL_VGA

targets		:= vmlinux.bin setup.bin setup.elf bzImage
targets		+= fdimage fdimage144 fdimage288 image.iso mtools.conf
subdir-		:= compressed

setup-y		+= a20.o bioscall.o cmdline.o copy.o cpu.o cpucheck.o
setup-y		+= early_serial_console.o edd.o header.o main.o mca.o memory.o
setup-y		+= pm.o pmjump.o printf.o regs.o string.o tty.o video.o
setup-y		+= video-mode.o version.o
setup-$(CONFIG_X86_APM_BOOT) += apm.o

# The link order of the video-*.o modules can matter.  In particular,
# video-vga.o *must* be listed first, followed by video-vesa.o.
# Hardware-specific drivers should follow in the order they should be
# probed, and video-bios.o should typically be last.
setup-y		+= video-vga.o
setup-y		+= video-vesa.o
setup-y		+= video-bios.o

targets		+= $(setup-y)
hostprogs-y	:= mkcpustr tools/build

HOST_EXTRACFLAGS += -I$(srctree)/tools/include $(LINUXINCLUDE) \
	            -D__EXPORTED_HEADERS__

$(obj)/cpu.o: $(obj)/cpustr.h

quiet_cmd_cpustr = CPUSTR  $@
      cmd_cpustr = $(obj)/mkcpustr > $@
targets		+= cpustr.h
$(obj)/cpustr.h: $(obj)/mkcpustr FORCE
	$(call if_changed,cpustr)

# ---------------------------------------------------------------------------

# How to compile the 16-bit code.  Note we always compile for -march=i386,
# that way we can complain to the user if the CPU is insufficient.
KBUILD_CFLAGS	:= $(LINUXINCLUDE) -g -Os -D_SETUP -D__KERNEL__ \
		   -DDISABLE_BRANCH_PROFILING \
		   -Wall -Wstrict-prototypes \
		   -march=i386 -mregparm=3 \
		   -include $(srctree)/$(src)/code16gcc.h \
		   -fno-strict-aliasing -fomit-frame-pointer -fno-pic \
		   $(call cc-option, -ffreestanding) \
		   $(call cc-option, -fno-toplevel-reorder,\
			$(call cc-option, -fno-unit-at-a-time)) \
		   $(call cc-option, -fno-stack-protector) \
		   $(call cc-option, -mpreferred-stack-boundary=2)
KBUILD_CFLAGS	+= $(call cc-option, -m32)
KBUILD_AFLAGS	:= $(KBUILD_CFLAGS) -D__ASSEMBLY__
GCOV_PROFILE := n

$(obj)/bzImage: asflags-y  := $(SVGA_MODE)

quiet_cmd_image = BUILD   $@
cmd_image = $(obj)/tools/build $(obj)/setup.bin $(obj)/vmlinux.bin > $@

	# 目标arch/x86/boot/bzImage，解决完依赖后
	# 由if_changed生成命令cmd_image
	# 即arch/x86/boot/tools/build
	#       arch/x86/boot/setup.bin arch/x86/boot/vmlinux.bin CURRENT > arch/x86/boot/bzImage
	# cat .version即显示内核代码编译的次数

$(obj)/bzImage: $(obj)/setup.bin $(obj)/vmlinux.bin $(obj)/tools/build FORCE
	$(call if_changed,image)
	@echo 'Kernel: $@ is ready' ' (#'`cat .version`')'

    # 依赖文件为compressed/vmlinux，进入compressed目录生成目标vmlinux

    # 然后使用objcopy复制出2进制文件
    # 例如: objcopy  -O binary -R .note -R .comment -S
    #         arch/x86/boot/compressed/vmlinux arch/x86/boot/vmlinux.bin
    # -O binary 以2进制格式输出
    # -R .note -R .comment 从输入文件中去掉.note .comment节
    # -S
    # --strip-all
    #     Do not copy relocation and symbol information from the source file.

OBJCOPYFLAGS_vmlinux.bin := -O binary -R .note -R .comment -S
$(obj)/vmlinux.bin: $(obj)/compressed/vmlinux FORCE
	$(call if_changed,objcopy)

    # setup.elf所依赖的对象
    # 给所有的setup-y项添加路径信息前缀

SETUP_OBJS = $(addprefix $(obj)/,$(setup-y))

sed-voffset := -e 's/^\([0-9a-fA-F]*\) . \(_text\|_end\)$$/\#define VO_\2 0x\1/p'

	# cmd_voffset命令
	# 例如: nm vmlinux | sed -n -e 's/^\([0-9a-fA-F]*\) . \(_text\|_end\)$/#define VO_\2 0x\1/p'
	#          > arch/x86/boot/voffset.h

quiet_cmd_voffset = VOFFSET $@
      cmd_voffset = $(NM) $< | sed -n $(sed-voffset) > $@

targets += voffset.h
$(obj)/voffset.h: vmlinux FORCE
	$(call if_changed,voffset)

sed-zoffset := -e 's/^\([0-9a-fA-F]*\) . \(startup_32\|input_data\|_end\|z_.*\)$$/\#define ZO_\2 0x\1/p'

quiet_cmd_zoffset = ZOFFSET $@
      cmd_zoffset = $(NM) $< | sed -n $(sed-zoffset) > $@

	# 压缩映像的偏移，依赖压缩后的映像文件

targets += zoffset.h
$(obj)/zoffset.h: $(obj)/compressed/vmlinux FORCE
	$(call if_changed,zoffset)


AFLAGS_header.o += -I$(obj)
$(obj)/header.o: $(obj)/voffset.h $(obj)/zoffset.h

    # 使用连接脚本setup.ld连接生成setup.elf，然后由objcopy为setup.bin

    # 例如: ld -m elf_i386   -T arch/x86/boot/setup.ld
    #         arch/x86/boot/a20.o arch/x86/boot/bioscall.o arch/x86/boot/cmdline.o
    #         arch/x86/boot/copy.o arch/x86/boot/cpu.o arch/x86/boot/cpucheck.o
    #         arch/x86/boot/early_serial_console.o arch/x86/boot/edd.o arch/x86/boot/header.o
    #         arch/x86/boot/main.o arch/x86/boot/mca.o arch/x86/boot/memory.o
    #         arch/x86/boot/pm.o arch/x86/boot/pmjump.o arch/x86/boot/printf.o arch/x86/boot/regs.o
    #         arch/x86/boot/string.o arch/x86/boot/tty.o arch/x86/boot/video.o
    #         arch/x86/boot/video-mode.o arch/x86/boot/version.o arch/x86/boot/apm.o
    #         arch/x86/boot/video-vga.o arch/x86/boot/video-vesa.o arch/x86/boot/video-bios.o
    #         -o arch/x86/boot/setup.elf

LDFLAGS_setup.elf	:= -T
$(obj)/setup.elf: $(src)/setup.ld $(SETUP_OBJS) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_setup.bin	:= -O binary
$(obj)/setup.bin: $(obj)/setup.elf FORCE
	$(call if_changed,objcopy)

$(obj)/compressed/vmlinux: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/compressed $@

# Set this if you want to pass append arguments to the
# bzdisk/fdimage/isoimage kernel
FDARGS =
# Set this if you want an initrd included with the
# bzdisk/fdimage/isoimage kernel
FDINITRD =

image_cmdline = default linux $(FDARGS) $(if $(FDINITRD),initrd=initrd.img,)

$(obj)/mtools.conf: $(src)/mtools.conf.in
	sed -e 's|@OBJ@|$(obj)|g' < $< > $@

# This requires write access to /dev/fd0
bzdisk: $(obj)/bzImage $(obj)/mtools.conf
	MTOOLSRC=$(obj)/mtools.conf mformat a:			; sync
	syslinux /dev/fd0					; sync
	echo '$(image_cmdline)' | \
		MTOOLSRC=$(src)/mtools.conf mcopy - a:syslinux.cfg
	if [ -f '$(FDINITRD)' ] ; then \
		MTOOLSRC=$(obj)/mtools.conf mcopy '$(FDINITRD)' a:initrd.img ; \
	fi
	MTOOLSRC=$(obj)/mtools.conf mcopy $(obj)/bzImage a:linux	; sync

# These require being root or having syslinux 2.02 or higher installed
fdimage fdimage144: $(obj)/bzImage $(obj)/mtools.conf
	dd if=/dev/zero of=$(obj)/fdimage bs=1024 count=1440
	MTOOLSRC=$(obj)/mtools.conf mformat v:			; sync
	syslinux $(obj)/fdimage					; sync
	echo '$(image_cmdline)' | \
		MTOOLSRC=$(obj)/mtools.conf mcopy - v:syslinux.cfg
	if [ -f '$(FDINITRD)' ] ; then \
		MTOOLSRC=$(obj)/mtools.conf mcopy '$(FDINITRD)' v:initrd.img ; \
	fi
	MTOOLSRC=$(obj)/mtools.conf mcopy $(obj)/bzImage v:linux	; sync

fdimage288: $(obj)/bzImage $(obj)/mtools.conf
	dd if=/dev/zero of=$(obj)/fdimage bs=1024 count=2880
	MTOOLSRC=$(obj)/mtools.conf mformat w:			; sync
	syslinux $(obj)/fdimage					; sync
	echo '$(image_cmdline)' | \
		MTOOLSRC=$(obj)/mtools.conf mcopy - w:syslinux.cfg
	if [ -f '$(FDINITRD)' ] ; then \
		MTOOLSRC=$(obj)/mtools.conf mcopy '$(FDINITRD)' w:initrd.img ; \
	fi
	MTOOLSRC=$(obj)/mtools.conf mcopy $(obj)/bzImage w:linux	; sync

isoimage: $(obj)/bzImage
	-rm -rf $(obj)/isoimage
	mkdir $(obj)/isoimage
	for i in lib lib64 share end ; do \
		if [ -f /usr/$$i/syslinux/isolinux.bin ] ; then \
			cp /usr/$$i/syslinux/isolinux.bin $(obj)/isoimage ; \
			break ; \
		fi ; \
		if [ $$i = end ] ; then exit 1 ; fi ; \
	done
	cp $(obj)/bzImage $(obj)/isoimage/linux
	echo '$(image_cmdline)' > $(obj)/isoimage/isolinux.cfg
	if [ -f '$(FDINITRD)' ] ; then \
		cp '$(FDINITRD)' $(obj)/isoimage/initrd.img ; \
	fi
	mkisofs -J -r -o $(obj)/image.iso -b isolinux.bin -c boot.cat \
		-no-emul-boot -boot-load-size 4 -boot-info-table \
		$(obj)/isoimage
	isohybrid $(obj)/image.iso 2>/dev/null || true
	rm -rf $(obj)/isoimage

bzlilo: $(obj)/bzImage
	if [ -f $(INSTALL_PATH)/vmlinuz ]; then mv $(INSTALL_PATH)/vmlinuz $(INSTALL_PATH)/vmlinuz.old; fi
	if [ -f $(INSTALL_PATH)/System.map ]; then mv $(INSTALL_PATH)/System.map $(INSTALL_PATH)/System.old; fi
	cat $(obj)/bzImage > $(INSTALL_PATH)/vmlinuz
	cp System.map $(INSTALL_PATH)/
	if [ -x /sbin/lilo ]; then /sbin/lilo; else /etc/lilo/install; fi

install:
	sh $(srctree)/$(src)/install.sh $(KERNELRELEASE) $(obj)/bzImage \
		System.map "$(INSTALL_PATH)"
