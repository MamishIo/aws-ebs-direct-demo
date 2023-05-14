#!/usr/bin/env python3
import boto3, sys
from crc32c import crc32c
from functools import reduce
from math import ceil
from re import split
from struct import pack, unpack

#boto3.set_stream_logger(name='', level=10, format_string=None)

ebs = boto3.client('ebs')
#source_snapshot = 'snap-0be4808432e413a4e' # home-sandbox
#source_snapshot = 'snap-00d63447f7392e19c' # work-main
#source_snapshot = 'snap-08b0e1d7e4fef086b' # home-sb2-prod/baro

try:
    source_snapshot = sys.argv[1]
except IndexError:
    print(f'Usage: python3 ebsd-interactive.py <snapshot-id>')
    sys.exit(1)
enable_section_pause = False

def section_pause():
    if enable_section_pause:
        input('\nPress enter to continue...')
    else:
        pass


## PART 1: EBS Direct API access
#
# Lists all available snapshot blocks and sets up functions to read block data.
# Block data is permanently cached so subsequent reads don't need more API calls.
#
# Notice that EBS Direct blocks are 512KiB, so 1024x as big as LBA blocks (512B).
# Unless reads are very sparse, this means very few API calls are needed for any given number of LBA or filesystem
# block reads.

block_tokens = {}
list_blocks_args = {'SnapshotId': source_snapshot}
while True:
    response = ebs.list_snapshot_blocks(**list_blocks_args)
    for b in response['Blocks']:
        block_tokens[b['BlockIndex']] = b['BlockToken']
    if next_token := response.get('NextToken'):
        list_blocks_args['NextToken'] = next_token
    else:
        break

print(f'Got EBS API block tokens, e.g. first 2: {list(block_tokens.items())[:2]}')
section_pause()

def run(data, offset, count):
    return data[offset:offset+count]

block_cache = {}
def get_logical_block(lba_index):
    ebs_block_index = int(lba_index * 512 / 524288)
    ebs_block_offset = int(lba_index % 1024) * 512
    if ebs_block_index not in block_cache:
        print(f'(API call: fetching EBS block {ebs_block_index}...)')
        block_data = ebs.get_snapshot_block(
            SnapshotId=source_snapshot, 
            BlockIndex=ebs_block_index,
            BlockToken=block_tokens[ebs_block_index]
        )['BlockData'].read()
        block_cache[ebs_block_index] = block_data
    return run(block_cache[ebs_block_index], ebs_block_offset, 512)

# Utility functions for working with binary data:
# * Pretty printing
# * Flag/bitmask interpreting
# * GUID/UUID parsing

def pretty_print_bytes(bstring, title=None):
    if title:
        print(title)
    print(f'[binary data: {len(bstring)} bytes]')
    for i in range(0, len(bstring), 16):
        row = run(bstring, i, 16)
        print(f'{i:04x} | {row.hex(" ", -4)} | {str(row)}')

def assert_equals(what, actual, expected, ignorable=False):
    condition = actual == expected
    print(f'{what} = {condition}')
    if not condition:
        if ignorable:
            print(f'Warning: Assertion failed! Expected <{expected}> but got <{actual}>')   
        else:
            print(f'Error: Assertion failed! Expected <{expected}> but got <{actual}>') 
            sys.exit(1)
        

def print_flags(msg, mask, print_cleared, flag_to_name):
    fset = []
    fclear = []
    for (flag,name) in flag_to_name.items():
        if flag & mask:
            fset.append(name)
        else:
            fclear.append(name)
    full_mask = reduce(lambda a,b: a | b, flag_to_name.keys())
    unrecognised = mask & (~full_mask)
    if unrecognised:
        fclear.append(f'[unrecognised: {unrecognised:#x}]')
    print(f'{msg} {mask:#x}')
    print(f' ->   set: [{", ".join(fset)}]')
    if print_cleared:
        print(f' -> clear: [{", ".join(fclear)}]')

def parse_guid(bstring):
    # GUID binary-to-string is mixed-endian, which is why this is so confusing
    # (the '2s' should be an 'H', but it's big-endian so we have to change it around)
    gll, glh1, glh2, gbh3, gbs = unpack('< L H H 2s 6s', bstring)
    return f'{gll:08x}-{glh1:04x}-{glh2:04x}-{gbh3.hex()}-{gbs.hex()}'


## Part 2: Interpreting protective Master Boot Record (MBR)
#
# GPT-formatted disks include a dummy MBR for protection against older MBR-compatible software that might otherwise
# think this is free space. This MBR only has a single partition of type 0xEE that covers the entire disk.
#
# The very first disk block (LBA0) contains the entire MBR.

print()
mbr = get_logical_block(0)
pretty_print_bytes(mbr, 'Dump of MBR (LBA0):')

print()
mbr_partition_entry0 = run(mbr, 446, 16)
pretty_print_bytes(mbr_partition_entry0, "Dump of MBR PTE0:")
mbr_pte0_status, mbr_pte0_type, mbr_pte0_first_lba, mbr_pte0_num_sectors = unpack('< B 3x B 3x L L', mbr_partition_entry0)
print(f'PTE0 status: 0x{mbr_pte0_status:02x}')
print(f'PTE0 type: 0x{mbr_pte0_type:02x}')
print(f'PTE0 first LBA: {mbr_pte0_first_lba}')
print(f'PTE0 num sectors: {mbr_pte0_num_sectors}')
assert_equals('PTE0 has EFI partition type (0xEE)', mbr_pte0_type, 0xee)
assert_equals('PTE0 has EFI partition at LBA1', mbr_pte0_first_lba, 1)
mbr_sig = run(mbr, 510, 2)
pretty_print_bytes(mbr_sig, 'MBR signature:')
assert_equals('MBR signature is 0x55AA', mbr_sig, b'\x55\xAA')

section_pause()


## Part 3: Interpreting GUID Partition Table (GPT)
#
# GPT is part of the (Unified) Extensible Firmware Interface ((U)EFI), so this is more commonly called the "EFI
# partition table". Both the start and end of the disk contain a 1-LBA 'header' with metadata, followed by some number
# of blocks containing partition table entries. There must always be at least 128 entries in the table and very few
# systems every need this many partitions, so it's a pretty safe assumption that most disks will have exactly 128.
#
# GUIDs are used for both the type of the partition and the unique partition ID, i.e. every Linux filesystem partition
# has the same type GUID but its own unique partition GUID.
#
# GUIDs and UUIDs are almost exactly the same thing, though there are slight differences is presentation/formatting.
# EFI sticks closely to the classic Windows-defined GUID format.

print()
efi_header = get_logical_block(1)
pretty_print_bytes(efi_header, 'Dump of main EFI header (LBA1):')

print()
efi_sig, efi_rev, efi_header_sz = unpack('< 8s L L', run(efi_header, 0, 16))
assert_equals('EFI signature says "EFI PART"', efi_sig, b'EFI PART')
assert_equals('EFI revision is 1.0', efi_rev, 1 << 16) # The revision is structured weirdly, '00 00 01 00' for some reason
assert_equals('EFI header size is 92 bytes', efi_header_sz, 92)
efi_current_lba, efi_backup_lba = unpack('< Q Q', run(efi_header, 24, 16))
assert_equals('Main EFI header located at LBA1:', efi_current_lba, 1)
(efi_backup_sig,) = unpack('< 8s', get_logical_block(efi_backup_lba)[:8])
assert_equals(f'Backup EFI header sig at backup LBA {efi_backup_lba}', efi_backup_sig, b'EFI PART')
(efi_first_usable_lba,) = unpack('< 8s', run(efi_header, 40, 8))
efi_pte_table_lba, efi_num_ptes, efi_pte_size = unpack('< Q L L', run(efi_header, 72, 16))
assert_equals('EFI partition table LBA is 2', efi_pte_table_lba, 2)
assert_equals('EFI partition table has 128 entries', efi_num_ptes, 128)
assert_equals('EFI partition table entry size is 128', efi_pte_size, 128)

# Read as many table entries as indicated above (variable number of blocks used).
# This script assumes 128 so it's not really variable, but a proper implementation would be.

print()
efi_ptes = []
for i in range(int(128 / 4)):
    block = get_logical_block(efi_pte_table_lba + i)
    for j in range(4):
        block_offset = 128 * j
        efi_ptes.append(run(block, block_offset, 128))

# Identify Linux filesystem partitions
# This script assumes exactly 1 filesystem present.

print()
num_used_partitions = 0
linux_fs_partitions = []
for i in range(128):
    pte = efi_ptes[i]
    part_type_guid = parse_guid(pte[:16])
    part_type_name = {
        '00000000-0000-0000-0000-000000000000': 'UNUSED',
        '0FC63DAF-8483-4772-8E79-3D69D8477DE4': 'LINUX_FILESYSTEM',
        '21686148-6449-6E6F-744E-656564454649': 'BIOS_BOOT_PARTITION',
        'C12A7328-F81F-11D2-BA4B-00A0C93EC93B': 'EFI_SYSTEM_PARTITION'
    }.get(part_type_guid.upper())
    if not part_type_name:
        print(f'EFI partition {i} GUID not recognised ({part_type_guid})!')
    if part_type_name != 'UNUSED':
        num_used_partitions += 1
        print(f'EFI partition {i} has type "{part_type_name}" ({part_type_guid})')
        pretty_print_bytes(pte, "Partition table entry:")
    if part_type_name == 'LINUX_FILESYSTEM':
        linux_fs_partitions.append(pte)
print(f'Num partition slots used: {num_used_partitions}')
print(f'Located {len(linux_fs_partitions)} Linux filesystem partitions')
assert_equals('Has exactly 1 Linux filesystem', len(linux_fs_partitions), 1)

section_pause()

# Find the filesystem partition's location on disk

print()
linux_pte = linux_fs_partitions[0]
linux_pte_guid = parse_guid(linux_pte[16:32])
print(f'Linux filesystem partition has unique ID {linux_pte_guid}')
linux_fs_first_lba, linux_fs_last_lba = unpack('< Q Q', run(linux_pte, 32, 16))
print(f'Linux fileystem LBA range is {linux_fs_first_lba}..{linux_fs_last_lba} (inclusive)')
print(f'Linux filesystem size is {int((linux_fs_last_lba - linux_fs_first_lba) * 512 / 1024**2)} MiB')
linux_pte_name = linux_pte[56:128].split(b'\x00')[0].decode("utf-16le")
print(f'Linux filesystem partition name is "{linux_pte_name}" (these are usually empty)')


## Part 4: Reading the ext4 superblock (hopefully)
#
# Assuming this is an ext4 filesystem, we need to read the first filesystem block and interpret it as a superblock to
# get metadata about this filesystem. If this isn't ext4, we'll get a signature/magic failure somewhere.
#
# Note that from now on we generally work in filesystem blocks, not LBA blocks. Filesystem blocks are usually 4KiB, so
# 8x larger than LBA. The exact size is defined in the superblock, but 4KiB is typical.

# Skip the first 1024 bytes - ext4 block group 0 leaves these open for arbitrary boot use.

print()
linux_fs_pad0 = get_logical_block(linux_fs_first_lba)
assert_equals("Filesystem group0 first block is padding (zeroes)", linux_fs_pad0, bytes(512))
linux_fs_pad1 = get_logical_block(linux_fs_first_lba + 1)
assert_equals("Filesystem group0 second block is padding (zeroes)", linux_fs_pad1, bytes(512))

# Grab the next 1024 bytes. Theoretically the superblock can take up the entire rest of the filesystem block (so up to
# 3072 bytes for 4KiB block) but the current superblock structure is max 1024.

section_pause()

linux_fs_sb = get_logical_block(linux_fs_first_lba + 2) + get_logical_block(linux_fs_first_lba + 3)
pretty_print_bytes(linux_fs_sb, 'Dump of first superblock:')

# Parse all the important sizing information from superblock, and verify magic bytes match an ext* filesystem

print()
(sb_inodes_count, sb_blocks_count_lo, sb_r_blocks_count_lo, sb_free_blocks_count_lo, sb_free_inodes_count,
 sb_first_data_block, sb_log_block_size, sb_log_cluster_size, sb_blocks_per_group, sb_clusters_per_group,
 sb_inodes_per_group, sb_mtime, sb_wtime, sb_mnt_count, sb_max_mnt_count, sb_magic, sb_state
) = unpack('< 13L H H 2s H', run(linux_fs_sb, 0, 60))
(sb_blocks_count_hi, sb_r_blocks_count_hi, sb_free_blocks_count_hi) = unpack('<3L', run(linux_fs_sb, 0x150, 12))
sb_blocks_count_i64 = (sb_blocks_count_hi << 32) + sb_blocks_count_lo
sb_block_size = 2**(sb_log_block_size + 10)
print('Filesystem superblock information:')
print(f'inodes count = {sb_inodes_count}')
print(f'blocks count = {sb_blocks_count_i64}')
print(f'reserved blocks count = {(sb_r_blocks_count_hi << 32) + sb_r_blocks_count_lo}')
print(f'free blocks count = {(sb_free_blocks_count_hi << 32) + sb_free_blocks_count_lo}')
print(f'free inodes count = {sb_free_inodes_count}')
print(f'first data block = {sb_first_data_block}')
print(f'log2 of block size = {sb_log_block_size + 10} (size={sb_block_size})')
print(f'log2 of cluster size = {sb_log_cluster_size + 10} (size={2**(sb_log_cluster_size + 10)})')
print(f'blocks per group = {sb_blocks_per_group}')
print(f'clusters per group = {sb_clusters_per_group}')
print(f'inodes per group = {sb_inodes_per_group}')
print(f'mount time (epoch) = {sb_mtime}')
print(f'write time (epoch) = {sb_wtime}')
print(f'mount count = {sb_mnt_count}')
print(f'max mount count (advisory) = {sb_max_mnt_count}')
print(f'magic bytestring = 0x{sb_magic.hex()}')
print(f'state = {sb_state:0b}')

print()
assert_equals('Superblock has magic bytes 0x53ef for an ext(2|3|4) filesystem', sb_magic, b'\x53\xef')  

(sb_first_ino, sb_inode_size, sb_block_group_nr) = unpack('< L H H', run(linux_fs_sb, 0x54, 8))
print()
print(f'first non-reserved inode = {sb_first_ino}')
print(f'inode size = {sb_inode_size}')
print(f'block group number = {sb_block_group_nr}')

# Parse and verify feature flags in use by the filesystem. The implementation error behaviour is different for each of
# the 3 feature flag fields. If a system does not support or recognise a given flag, it should:
# * For compat: Continue to mount. These features are generally backwards compatible.
# * For incompat: Do not attempt to mount. These features fundamentally change the filesystem and its structures in
#                 a way that is not backwards compatible for reading or writing.
# * For ro_compat: Only attempt to mount as read-only. These features won't affect readers, but an implementation
#                  attempting to write the filesystem would unintentionally corrupt something.

print()
(sb_feature_compat, sb_feature_incompat, sb_feature_ro_compat) = unpack('< L L L', run(linux_fs_sb, 0x5c, 12))

print_flags('Compat features:', sb_feature_compat, True, {
    0x1: 'DIR_PREALLOC',
    0x2: 'IMAGIC_INODES',
    0x4: 'HAS_JOURNAL',
    0x8: 'EXT_ATTR',
    0x10: 'RESIZE_INODE',
    0x20: 'DIR_INDEX',
    0x40: 'LAZY_BG',
    0x80: 'EXCLUDE_INODE'
})
print_flags('Incompat features:', sb_feature_incompat, True, {
    0x1: 'COMPRESSION',
    0x2: 'FILETYPE',
    0x4: 'RECOVER',
    0x8: 'JOURNAL_DEV',
    0x10: 'META_BG',
    0x40: 'EXTENTS',
    0x80: '64BIT',
    0x100: 'MMP',
    0x200: 'FLEX_BG',
    0x400: 'EA_INODE',
    0x1000: 'DIRDATA',
    0x2000: 'CSUM_SEED',
    0x4000: 'LARGEDIR',
    0x8000: 'INLINE_DATA',
    0x10000: 'ENCRYPT'
})
print_flags('Read-only compat features:', sb_feature_ro_compat, True, {
    0x1: 'SPARSE_SUPER',
    0x2: 'LARGE_FILE',
    0x4: 'BTREE_DIR',
    0x8: 'INODE_HUGE_FILE',
    0x10: 'GDT_CSUM',
    0x20: 'DIR_NLINK',
    0x40: 'EXTRA_ISIZE',
    0x80: 'HAS_SNAPSHOT',
    0x100: 'QUOTA',
    0x200: 'BIGALLOC',
    0x400: 'METADATA_CSUM',
    0x800: 'REPLICA',
    0x1000: 'READONLY',
    0x2000: 'PROJECT'
})

# Designed to work with exactly (FILETYPE | EXTENTS | 64BIT | FLEX_BG)
assert_equals('Has matching incompat feature flags', sb_feature_incompat, 0x0002c2)
# Expects METADATA_CSUM and EXTRA_ISIZE, otherwise doesn't care (might consider adding INODE_HUGE_FILE)
assert_equals('Has expected ro_compat feature flags', sb_feature_ro_compat & 0x440, 0x440)

# Miscellaneous superblock sizing information

(sb_uuid, sb_volume_name, sb_last_mounted) = unpack('< 16s 16s 64s', run(linux_fs_sb, 0x68, 16+16+64))
print()
print(f'volume GUID = {parse_guid(sb_uuid)}')
print(f'volume name = {sb_volume_name}')
print(f'volume last mount dir = {sb_last_mounted}')

(sb_desc_size,) = unpack('<H', run(linux_fs_sb, 0xfe, 2))
print()
print(f'group descriptor size = {sb_desc_size}')
assert_equals('Filesystem uses 64-byte GDTs', sb_desc_size, 64)

(sb_log_groups_per_flex,) = unpack('< b', run(linux_fs_sb, 0x174, 1))
print()
print(f'log2 of flex group size = {sb_log_groups_per_flex} (size={2**sb_log_groups_per_flex})')

def get_fs_raw_block(fs_index):
    # Derivation: ration = block_size / 512 = 2^(log2bs + 10) / 2^9 = 2^(log2bs + 10 - 9)) = 2^(log2bs + 1)
    num_logical_per_fs_block = 2**(sb_log_block_size + 1)  
    lba_start = linux_fs_first_lba + (fs_index * num_logical_per_fs_block)
    lbas = [get_logical_block(lba_start + i) for i in range(num_logical_per_fs_block)]
    return b''.join(lbas)


## Part 5: Interpreting Block Group Descriptors
#
# The filesystem is divided into block groups of `sb_blocks_per_group` filesystem blocks. Immediately following the
# superblock is a list/table of group descriptors with group metadata. E.g. the first (index=0) descriptor in the table
# is for block group 0, containing blocks 0-32767 and inodes 1-`sb_inodes_per_group`. To read those blocks and inodes,
# we have to follow the pointers listed in group 0's descriptor.
#
# The most important information here (for our purposes) is the inode table pointer, which points to the first block
# containing inode entries. This lets us locate any inode in the system.

section_pause()

fs_num_block_groups = ceil(sb_blocks_count_i64 / sb_blocks_per_group)
print()
print(f'total number of block groups = {fs_num_block_groups}')

fs_gdts_exact_size = fs_num_block_groups * 64
fs_gdts_num_blocks = ceil(fs_gdts_exact_size / sb_block_size)
fs_gdt_data = b''.join([get_fs_raw_block(1 + i) for i in range(fs_gdts_num_blocks)])[:fs_gdts_exact_size]

inode_table_ptrs = []
for gdt_index in range(fs_num_block_groups):
    data_start = gdt_index * 64
    data = run(fs_gdt_data, data_start, 64)
    i32 = lambda hi, lo: (unpack('<H', run(data, hi, 2))[0] << 16) + unpack('<H', run(data, lo, 2))[0]
    i64 = lambda hi, lo: (unpack('<L', run(data, hi, 4))[0] << 32) + unpack('<L', run(data, lo, 4))[0]
    gdt_block_bitmap_ptr = i64(0x20, 0x0)
    gdt_inode_bitmap_ptr = i64(0x24, 0x4)
    gdt_inode_table_ptr = i64(0x28, 0x8)
    inode_table_ptrs.append(gdt_inode_table_ptr)
    gdt_free_blocks_count = i32(0x2c, 0xc)
    gdt_free_inodes_count = i32(0x2e, 0xe)
    gdt_used_dirs_count = i32(0x30, 0x10)
    gdt_flags, = unpack('<H', run(data, 0x12, 2))
    gdt_block_bitmap_csum = i32(0x38, 0x18)
    gdt_inode_bitmap_csum = i32(0x3a, 0x1a)
    gdt_itable_unused = i32(0x32, 0x1c)
    gdt_checksum, = unpack('<H', run(data, 0x1e, 2))
    if gdt_flags == 0x7:
        # Uninitialized block, don't bother printing
        continue
    print()
    pretty_print_bytes(data, f'Block group {gdt_index} descriptor:')
    # These flags are a bit confusing, but basically, INODE_ZEROED means "in use".
    # The *_UNINIT flags mean either blocks or inodes are not initialized, but it's unclear what that means when 
    # INODE_ZEROED shows up in the same field.
    print_flags(f'Group flags for group #{gdt_index}:', gdt_flags, False, {
        0x1: 'INODE_UNINIT',
        0x2: 'BLOCK_UNINIT',
        0x4: 'INODE_ZEROED'
    })
    print(f'block bitmap ptr = {gdt_block_bitmap_ptr:#016x}')
    print(f'inode bitmap ptr = {gdt_inode_bitmap_ptr:#016x}')
    print(f'inode table ptr = {gdt_inode_table_ptr:#016x}')
    print(f'free blocks = {gdt_free_blocks_count}, free inodes = {gdt_free_inodes_count}, used dirs = {gdt_used_dirs_count}')

    # TODO: I have not been able to get this checksum to match no matter what calculation/steps I use.
    gdt_copy_zero_sig = bytearray(data)
    gdt_copy_zero_sig[0x1e:0x1e+2] = b'\x00\x00'
    csum = crc32c(sb_uuid, ~0)
    csum = crc32c(pack('<L', gdt_index), csum)
    csum = crc32c(gdt_copy_zero_sig, csum)

    print(f'Expected checksum = {gdt_checksum:#010x}, calculated checksum = {csum:#010x}')
    assert_equals('GDT has expected checksum', csum & 0xffff, gdt_checksum, ignorable=True)

section_pause()


## Part 6: Define function to locate and read inode descriptors
#
# inodes are (at least in my test filesystems) a padded 256-byte descriptor. These are divided across block groups,
# so to find a given inode you need to calculate what block group it's in, grab the inode table pointer from the
# matching group descriptor, calculate which block the inode is in relative to that pointer, and finally calculate
# the offset within that block.

def get_inode(inode_number):
    inode_index = inode_number - 1  # There is no inode 1
    
    block_group_num = int(inode_index / sb_inodes_per_group)
    block_group_offset = int(inode_index % sb_inodes_per_group)
    print(f'get_inode({inode_number}): index is {block_group_offset} in block group {block_group_num}')

    inode_table_offset = block_group_offset * sb_inode_size
    inode_table_block_num = int(inode_table_offset / sb_block_size)
    inode_table_block_offset = int(inode_table_offset % sb_block_size)
    print(f'get_inode({inode_number}): byte offset is {inode_table_block_offset} (length={sb_inode_size}) in block {inode_table_block_num} relative to table')
    
    inode_table_base = inode_table_ptrs[block_group_num]
    inode_table_exact = inode_table_base + inode_table_block_num
    inode_block = get_fs_raw_block(inode_table_exact)
    print(f'get_inode({inode_number}): exact filesystem block is {inode_table_exact} ({inode_table_base} + {inode_table_block_num})')
    
    return run(inode_block, inode_table_block_offset, sb_inode_size)


## Part 7: Define function to load file/block data for an inode
#
# The cool part! Here we read the inode metadata, which most importantly (for us) contains the size, the file type
# (this is an extension from the FILETYPE incompat feature in superblock), and 60 bytes of content in various formats.
#
# For most types we're interested in (files and directories), this content is an extent tree node pointing to
# filesystem data blocks; see `copy_extent_data` for information. Symbolic links are a unique case: if the path for a
# symlink is shorter than 60 bytes, it's placed directly in the inode without using extents.
#
# Note that this function expects the inode to use extents. Real implementations would have ext2/3-style indirect block
# addressing support for backwards compatibility, but I haven't bothered.

def get_inode_data(inode_number, assert_ftype=None, metadata_only=False):

    inode_desc = get_inode(inode_number)

    print()
    pretty_print_bytes(inode_desc, f'inode {inode_number} descriptor data')

    (inode_mode, inode_uid, inode_size_lo, inode_atime, inode_ctime, inode_mtime, inode_dtime, inode_gid_lo,
        inode_links_count, inode_blocks_lo, inode_flags, inode_version, inode_content,
        inode_generation, inode_file_acl_lo, inode_size_hi, # 4 bytes (i_obso_faddr) ignored, 
        inode_blocks_hi, inode_file_acl_hi, 
        inode_uid_hi, inode_gid_hi, inode_checksum_lo, # 2 bytes (osd2.l_i_reversed) ignored
        inode_extra_isize, inode_checksum_hi, inode_ctime_extra, inode_mtime_extra,
        inode_atime_extra, inode_crtime, inode_crtime_extra, inode_version_hi, inode_projid
    ) = unpack(f'< 2H 5L 2H 3L 60s 3L 4x 5H 2x 2H 7L {256 - 160}x', inode_desc)

    print()
    # Most of these flags are unimplemented or just not relevant. Mostly a curiosity.
    print_flags(f'inode {inode_number} flags:', inode_flags, True, {
        0x1: 'SECRM', 0x2: 'UNRM', 0x4: 'COMPR', 0x8: 'SYNC', 0x10: 'IMMUTABLE', 0x20: 'APPEND', 0x40: 'NODUMP',
        0x80: 'NOATIME', 0x100: 'DIRTY', 0x200: 'COMPRBLK', 0x400: 'NOCOMPR', 0x800: 'ENCRYPT', 0x1000: 'INDEX',
        0x2000: 'IMAGIC', 0x4000: 'JOURNAL_DATA', 0x8000: 'NOTAIL', 0x10000: 'DIRSYNC', 0x20000: 'TOPDIR',
        0x40000: 'HUGE_FILE', 0x80000: 'EXTENTS', 0x200000: 'EA_INODE', 0x400000: 'EOFBLOCKS', 0x1000000: 'SNAPFILE',
        0x4000000: 'SNAPFILE_DELETED', 0x8000000: 'SNAPFILE_SHRUNK', 0x10000000: 'INLINE_DATA',
        0x20000000: 'PROJINHERIT', 0x80000000: 'RESERVED'
    })

    inode_size = (inode_size_hi << 32) + inode_size_lo
    inode_permissions = inode_mode & 0xfff
    inode_file_type = inode_mode & 0xf000
    inode_file_type_name = {
        0x1000: 'FIFO', 0x2000: 'FCHR', 0x4000: 'FDIR', 0x6000: 'FBLK',
        0x8000: 'FREG', 0xA000: 'FLNK', 0xC000: 'FSOCK'
    }[inode_file_type]

    print(f'inode {inode_number} size = {inode_size}')
    print(f'inode {inode_number} permissions = {inode_permissions:04o}, file type = {inode_file_type:#x} ({inode_file_type_name})')
    if assert_ftype:
        assert_equals(f'inode {inode_number} has expected ftype "{assert_ftype}"', inode_file_type_name, assert_ftype)

    section_pause()

    if metadata_only:
        return None  # Don't copy any actual block data

    data = bytearray(inode_size)
    # Symbolic links are a special case where the target dir may be written directly into the block
    # If this is the case, don't check for extent flag or try to read extent data
    if inode_file_type_name == 'FLNK' and inode_size < 60: # Docs say "less than 60 bytes" specifically
        data[0:inode_size] = inode_content[0:inode_size]
    else:
        assert_equals(f'inode {inode_number} uses extents', inode_flags & 0x80000, 0x80000)
        copy_extent_data(inode_content, data, inode_size)
    return data

# This function traverses an extent tree and copies the entire file's data into a buffer.
#
# Extents are effectively block ranges organised into a tree structure. So a single extent might encode information
# like "Blocks 0-99 of this file map to filesystem blocks 1000-1099". As long as the file isn't too sparse, this is a
# lot more efficient than the ext2/3 mapping method, since a tiny 12-byte extent can map up to 32768 contiguous
# filesystem blocks.
#
# Extent tree nodes start with a 12-byte header followed by some number of 12-byte entries, where all of the entries in
# a node are either leaf nodes, which encode the block ranges, or index nodes, which point to filesystem blocks
# containing more index or leaf nodes in the tree. The `depth` field in the header indicates leaf vs. index.
#
# Extents are variably sized since they can be found either directly inside the inode content field (60 bytes) or
# indirectly in filesystem blocks (typically 4 KiB). One advantage of this is that small or highly-contiguous files,
# i.e. files that only need 4 extent entries, can fit entirely into a leaf node in the inode content, meaning no
# indirection is needed to locate the file data blocks.

def copy_extent_data(extent_node, data_array, max_length):

    (eh_magic, eh_entries, eh_max, eh_depth) = unpack('< 4H 4x', extent_node[:12])
    print(f'Extent header magic = {eh_magic:#06x}')
    print(f'Extent header num entries = {eh_entries}')
    print(f'Extent header max entries = {eh_max}')
    print(f'Extent header depth = {eh_depth}')
    assert_equals('Extent header has magic number 0xf30a as first bytes', eh_magic, 0xf30a)

    for extent_index in range(eh_entries):
        extent = run(extent_node, 12 * (1 + extent_index), 12)
        print()
        pretty_print_bytes(extent, f'Extent entry {extent_index}:')

        if eh_depth > 0:
            # This is an index (non-leaf) extent tree node
            (ei_block, ei_leaf_lo, ei_leaf_hi) = unpack('< L L H 2x', 'extent')
            ei_leaf = ei_leaf_hi << 32 + ei_leaf_lo
            # Not sure what ei_block is for - maybe so you can skip parts of the tree when looking for specific ranges?
            print(f'Extent (index) starting block = {ei_block}')
            print(f'Extent (index) leaf block number = {ei_leaf}')
            # Despite the name, this doesn't have to be a leaf (can be another index)
            child_extent_node = get_fs_raw_block(ei_leaf)
            # Recursive call
            copy_extent_data(child_extent_node, data_array)
        else:
            # This is a leaf (depth=0) extent tree node
            (ee_block, ee_len, ee_start_hi, ee_start_lo) = unpack('< L H H L', extent)
            ee_start = (ee_start_hi << 32) + ee_start_lo
            ee_init = ee_len <= 32768
            ee_real_len = ee_len % 32768
            print(f'Extent (leaf) starting file block number = {ee_block}')
            print(f'Extent (leaf) is initialized = {ee_init}')
            print(f'Extent (leaf) real length (blocks) = {ee_real_len}')
            print(f'Extent (leaf) starting data block number = {ee_start}')
            assert_equals('Extent (leaf) is initialized', ee_init, True)
            for i in range(ee_real_len):
                data_offset = (ee_block + i) * sb_block_size
                data_block = ee_start + i
                # '#:014x' = 0x{zero-pad-12-digits}. Max is 4 digits from block size (at 64KiB max block size) + 8 from ee_block
                print(f'Copying {sb_block_size} bytes into offset {data_offset:#014x} from filestystem block {data_block}')
                # Copy only a portion of this block if we're in the final block (according to inode size)
                copy_len = max_length - data_offset
                if copy_len > sb_block_size:
                    copy_len = sb_block_size
                data_array[data_offset:data_offset+copy_len] = get_fs_raw_block(data_block)[:copy_len]


## Part 8: Define function to read directory entry data from FDIR inodes
#
# Ext4 directories are encoded in the data for FDIR-type inodes. The basic encoding is the 'classic'/linear encoding,
# which is just a big table of dynamically-sized (depending on name length) directory entries, which primarily contain
# a name, an inode number and the file type (dependent on incompat feature FILETYPE).
#
# If the compat feature DIR_INDEX is enabled, it's possible for an additional high-performance dir index, know as
# HTree, to be stuffed into the 'unused' directory entries. Since this is stuffed into 'unused' entries, we can just
# ignore it and treat this like a linear directory (much simpler).

def list_linear_directory(dir_data):

    print()
    print(f'Parsing {len(dir_data)} bytes of directory content')
    result_dirs = {}

    # Since entries are dynamically-sized, this cursor advances through the data based on each entry's length.
    # We know we are finished when the cursor hits end-of-file.
    dirent_cursor = 0
    while dirent_cursor < len(dir_data):
        dirent_run = lambda offs, count: run(dir_data, dirent_cursor+offs, count)
        (dirent_inode, dirent_len, dirent_name_len, dirent_ftype
            ) = unpack('< L H B B', dirent_run(0, 8))
        dirent_name = dirent_run(8, dirent_name_len).decode('ascii')
        # Note this mapping is subtly different to the one in get_inode_data()
        dirent_ftype_name = {
            0: 'Unknown', 1: 'Regular file', 2: 'Directory', 3: 'Character device',
            4: 'Block device', 5: 'FIFO', 6: 'Socket', 7: 'Symbolic link',
            0xde: '[checksum]'
        }[dirent_ftype]
        print(f'dirent (offset {dirent_cursor}): inode = {dirent_inode}, lengths = {dirent_len}:{dirent_name_len}, type = {dirent_ftype} ({dirent_ftype_name})')
        
        if dirent_ftype == 0xde:
            assert_equals('Fake checksum dirent has inode==0', dirent_inode, 0)
            assert_equals('Fake checksum dirent has 12-byte record length', dirent_len, 12)
            assert_equals('Fake checksum dirent has 0-length name', dirent_name_len, 0)
            dirent_checksum, = unpack('<L', dirent_run(8,4))
            print(f'Checksum value = {dirent_checksum:#010x}')
        
        if dirent_inode > 0:
            print(f'dirent name = "{dirent_name}"')
            # Tuples are a bit of code smell, but it's not super bad in this case
            result_dirs[dirent_name] = (dirent_inode, dirent_ftype_name)
        else:
            # Note: inode==0 always means ignore/unused; checksum above is just one special case of that.
            print(f'Not adding dirent to results since it has a 0 inode value')
        
        dirent_cursor += dirent_len

    return result_dirs


## Part 9: Spin up a CLI session to play around with directories and files
#
# This is a quick and dirty implementation of a shell with basic cd/ls/cat/xxd commands. It starts at inode 2, which is
# the reserved/special inode number for the root dir, and allows moving around to relative directories and printing
# files as text or binary data.
#
# Some key things that are missing:
# * Can only work with file/dirs relative to the current directory (i.e. no absolute names).
# * For the same reason as above, cannot follow symlinks.

cwd_inode = 2
cwd_path = []
cwd_dirents = list_linear_directory(get_inode_data(2, assert_ftype='FDIR'))

def change_cwd(inode_number):
    global cwd_inode
    global cwd_dirents
    new_dir_data = get_inode_data(inode_number, assert_ftype='FDIR')
    cwd_dirents = list_linear_directory(new_dir_data)
    cwd_inode = inode_number

def relative_dirent(name):
    if de := cwd_dirents.get(name):
        if (ftype := de[1]) == 'Directory':
            return de
        else:
            print(f'"{name}" is not a directory (type: {ftype})')
            return None
    else:
        print(f'No such relative directory "{name}"')
        return None

def repl():

    while True:

        print(f'\nAt inode {cwd_inode} ({"/"+"/".join(cwd_path)})')
        input_line = input(f'> ')
        input_line_tokens = split(r'\s+', input_line)
        if not input_line_tokens:
            continue # No command entered, don't do anything
        command = input_line_tokens[0]
        input_args = input_line_tokens[1:]
        
        def arg(num):
            if len(input_args) > num:
                return input_args[num]
            else:
                return None

        if command == 'help':
            print(f'Available commands:')
            print(f'    cd [file]: Change to given relative directory, or root dir if none specified')
            print(f'    ls [file]: List child directory, or current directory if none specified')
            print(f'    cat <file>: Print file as text (note: does not enforce inode/file type)')
            print(f'    xxd <file>: Print file as formatted binary (not: does not enforce inode/file type)')
            print(f'    stat <file>: Print inode information for a file')
        elif command == 'cd':
            command_cd(arg)
        elif command == 'ls':
            command_ls(arg)
        elif command == 'cat':
            command_with_data(arg, lambda data: print(data.decode('utf-8')))
        elif command == 'xxd':
            command_with_data(arg, lambda data: pretty_print_bytes(data))
        elif command == 'stat':
            command_stat(arg)
        elif command in ['quit', 'exit']:
            break
        else:
            print(f'Unknown command {command}, try "help"')

def command_cd(arg):
    global cwd_path
    if name := arg(0):
        if de := relative_dirent(name):
            new_inode = de[0]
            if name == '..':
                if not cwd_path:
                    print(f'Cannot chdir up from root dir')
                    return
                cwd_path.pop()
            elif name != '.': # do nothing if '.' (no-op)
                cwd_path.append(name)
        else:
            return # relative_dirent already prints error
    else:
        new_inode = 2
        cwd_path = []
    change_cwd(new_inode)

def command_ls(arg):
    if name := arg(0):
        if de := relative_dirent(name):
            ls_dir_data = get_inode_data(de[0])
            dirents = list_linear_directory(ls_dir_data)
        else:
            return # relative_dirent alreadys prints error
    else:
        dirents = cwd_dirents

    name_to_dirent = list(dirents.items())
    name_to_dirent.sort(key = lambda item: item[0])
    for name, de in name_to_dirent:
        print(f'"{name}" ({de[1]}, inode {de[0]})')

def command_with_data(arg, data_consumer):
    if name := arg(0):
        if de := cwd_dirents.get(name):
            file_data = get_inode_data(de[0])
            print()
            print(f'[Contents of "{name}" (inode {de[0]})]')
            data_consumer(file_data)
            print()
        else:
            print(f'No such relative file "{name}"')
            return
    else:
        print(f'Usage: cat <name>')

def command_stat(arg):
    if name := arg(0):
        if de := cwd_dirents.get(name):
            print()
            get_inode_data(de[0], metadata_only=True)  # return ignored
        else:
            print(f'No such relative file "{name}"')
            return
    else:
        print(f'Usage: stat <name>')

def print_stats():
    print('\nSession stats:')
    print(f'  EBS Direct block reads: {len(block_cache)}')
    print()

def main():
    try:
        repl()
    except KeyboardInterrupt:
        pass # Expected exit
    print_stats()

if __name__=="__main__":
    main()
