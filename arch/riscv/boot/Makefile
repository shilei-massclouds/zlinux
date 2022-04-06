#
# arch/riscv/boot/Makefile
#

OBJCOPYFLAGS_Image := -O binary -R .note -R .note.gnu.build-id -R .comment -S

targets := Image loader

$(obj)/Image: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/Image.gz: $(obj)/Image FORCE
	$(call if_changed,gzip)

install:
	$(CONFIG_SHELL) $(srctree)/$(src)/install.sh $(KERNELRELEASE) \
		$(obj)/Image System.map "$(INSTALL_PATH)"
