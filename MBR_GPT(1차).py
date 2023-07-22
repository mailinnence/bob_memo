import pytsk3

def detect_partition_table_type(image_path):
    # 이미지 파일을 열고 TSKImg_Info 개체 생성
    img = pytsk3.Img_Info(image_path)
    
    # TSK_VS_TYPE_DETECT 옵션을 사용하여 볼륨 시스템을 탐지하는 객체 생성
    vol = pytsk3.Volume_Info(img)
    
    # 파티션 테이블 유형 판별
    if vol.info.vstype == pytsk3.TSK_VS_TYPE_GPT:
        return "GPT"
    elif vol.info.vstype == pytsk3.TSK_VS_TYPE_DOS:
        return "MBR"
    else:
        return "Unknown"



# 이미지 파일 경로를 입력하세요
image_file_path = "C:\\Users\\maili\\OneDrive\\바탕 화면\\bob\\임시파일\\gpt_128.dd"

# 이미지 파일의 파티션 테이블 유형을 확인합니다
partition_table_type = detect_partition_table_type(image_file_path)
print("Partition Table Type:", partition_table_type)


if partition_table_type == "MBR":
    with open(image_file_path, "rb") as f:
        data = f.read()
        now = 446
        temp=0
        print(image_file_path)
        for i in range(4):
            print("----------------------------------------------------")
            FirstSector = int.from_bytes(data[now + 8:now + 12], byteorder='little')
            TotalSectors = int.from_bytes(data[now + 12:now + 16], byteorder='little')
            for y in range(16):
                if y==4:
                    FileSystemId = data[now+y]
            now+=16
            if FileSystemId == 0x07:
                print("Partition", i + 1)
                print("NTFS")
                print("First Sector:", FirstSector)
                print("Total Sectors:", TotalSectors)
            elif FileSystemId == 0x0B:
                print("Partition", i + 1)
                print("FAT32")
                print("First Sector:", FirstSector)
                print("Total Sectors:", TotalSectors)
            else:
                print("out of scope for homework")
            print("----------------------------------------------------\n")


elif partition_table_type == "GPT":
    with open(image_file_path, "rb") as f:
        # Read GPT header (LBA 1, 512 bytes)
        f.seek(512)
        gpt_header = f.read(512)

        # Calculate partition entry start LBA
        partition_entry_start_lba = int.from_bytes(gpt_header[72:80], byteorder='little')

        # Calculate partition entry size
        partition_entry_size = int.from_bytes(gpt_header[80:84], byteorder='little')

        # Calculate partition entry count
        partition_entry_count = int.from_bytes(gpt_header[84:88], byteorder='little')

        # Read GPT partition entries
        f.seek(partition_entry_start_lba * 512)
        partition_entries = f.read(partition_entry_size * partition_entry_count)

        # Parse partition entries
        for i in range(partition_entry_count):
            partition_start_lba = int.from_bytes(partition_entries[i*128 + 32:i*128 + 40], byteorder='little')
            partition_end_lba = int.from_bytes(partition_entries[i*128 + 40:i*128 + 48], byteorder='little')
            partition_type_guid = ' '.join(['{:02X}'.format(b) for b in partition_entries[i*128:i*128+16]])
            unique_partition_guid = ' '.join(['{:02X}'.format(b) for b in partition_entries[i*128+16:i*128+32]])

            print(f"Partition {i+1}")
            print(f"Partition Type GUID: {partition_type_guid}")
            print(f"Unique Partition GUID: {unique_partition_guid}")
            print(f"First LBA: {partition_start_lba}")
            print(f"Last LBA: {partition_end_lba}")
            print("----------------------------------------------------")
