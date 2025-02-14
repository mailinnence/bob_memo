import pytsk3
import tkinter
from tkinter import filedialog
import os



# gui
class MbrVbr:
    def __init__(self):
        self.window = tkinter.Tk()
        self.window.title("MBR_GPT")
        self.window.geometry("1280x700+50+30")
        self.window.resizable(True, True)

        menubar=tkinter.Menu(self.window)
        menu_1=tkinter.Menu(menubar, tearoff=0)
        menu_1.add_command(label="초기화")
        menubar.add_cascade(label="초기화", menu=menu_1)

        menu_2=tkinter.Menu(menubar, tearoff=0)
        menu_2.add_command(label="저장" )
        menubar.add_cascade(label="저장", menu=menu_2)        
        
        menu_3=tkinter.Menu(menubar, tearoff=0)
        menu_3.add_command(label="끝내기" )
        menubar.add_cascade(label="끝내기", menu=menu_3)        
        
        
        self.window.config(menu=menubar)

        # 분석결과
        self.analysis_image = tkinter.Text(self.window, width=63, height=29, state='disabled')
        self.analysis_image.configure(font=(40))
        self.analysis_image.grid(row=1, column=1, padx=8, pady=10)

        # 헥스 값
        self.analysis_hex = tkinter.Text(self.window, width=50, height=29, state='disabled')
        self.analysis_hex.configure(font=(40))
        self.analysis_hex.grid(row=1, column=2)

        plain_label_frame = tkinter.Frame(self.window)
        plain_label_frame.grid(row=2, column=1, columnspan=2, padx=10)

        plain_label = tkinter.Label(plain_label_frame, text="Select an image disk file with partition table type mbr or gpt and press the Analyze button.", font=("Arial", 12))
        plain_label.grid(row=1, column=2, padx=5, pady=6)

        # AnalysisFrame을 생성하여 label과 AnalysisButton을 Frame에 배치
        analysis_frame = tkinter.Frame(self.window)
        analysis_frame.grid(row=3, column=1, columnspan=2, padx=5, pady=5)

        self.analysis_file_location_text = tkinter.Text(analysis_frame, width=50, height=1, font=("Arial", 12), state='disabled')
        self.analysis_file_location_text.grid(row=2, column=1, padx=5)

        open_file_button = tkinter.Button(analysis_frame, text="Open", width=10, font=("Arial", 12), command=self.select_file)
        open_file_button.grid(row=2, column=2, padx=5)

        analysis_button = tkinter.Button(analysis_frame, text="Analysis", width=10, font=("Arial", 12) ,command=lambda:self.detect_partition_table_type(self.replace_slash2(self.analysis_file_location_text.get("1.0","end")[:-1])))
        analysis_button.grid(row=2, column=3, padx=5)
        self.window.mainloop()

    def replace_slash(self, path):
        return path.replace("/", "\\\\")   

    def replace_slash2(self, path):
        return path.replace("/", "\\") 
         
    def select_file(self):
        filename = filedialog.askopenfile(initialdir="/", title="Select file")
        if filename:
            file_path = filename.name
            #file_path = self.replace_slash2(file_path)
            self.analysis_file_location_text.config(state='normal')
            self.analysis_file_location_text.delete('1.0', tkinter.END)
            self.analysis_file_location_text.insert(tkinter.END, file_path)
            self.analysis_file_location_text.config(state='disabled')
            


# 파일분석 함수 -----------------------------------------------------------------------------------------------

    def detect_partition_table_type(self, image_path):
        # 이미지 파일을 열고 TSKImg_Info 개체 생성
        img = pytsk3.Img_Info(image_path)

        # TSK_VS_TYPE_DETECT 옵션을 사용하여 볼륨 시스템을 탐지하는 객체 생성
        vol = pytsk3.Volume_Info(img)

        # 파티션 테이블 유형 판별
        if vol.info.vstype == pytsk3.TSK_VS_TYPE_GPT:  # GPT
            self.gpt(image_path)
        elif vol.info.vstype == pytsk3.TSK_VS_TYPE_DOS:  # MBR
            self.mbr(image_path)
        else:
            return "Unknown"

    def mbr(self, image_path):
        self.analysis_image.config(state='normal')
        self.analysis_image.delete('1.0', tkinter.END)
        self.analysis_hex.config(state='normal')
        self.analysis_hex.delete('1.0', tkinter.END)
        with open(image_path, "rb") as f:
            data = f.read()
            now = 446
            
            for i in range(4):
                self.analysis_image.insert(tkinter.END,"")
                FirstSector = int.from_bytes(data[now + 8:now + 12], byteorder='little')
                TotalSectors = int.from_bytes(data[now + 12:now + 16], byteorder='little')

                self.analysis_hex.insert(tkinter.END,"Partition "+str(i+1)+"\n")
                hex1 = ' '.join(['{:02X}'.format(b) for b in data[i:i+200]])
                self.analysis_hex.insert(tkinter.END,hex1+"\n\n")
   
                for y in range(16):
                    if y == 4:
                        FileSystemId = data[now + y]
                now += 16
                if FileSystemId == 0x07:
                    self.analysis_image.insert(tkinter.END,"Partition "+ str(i + 1) +"\n")
                    self.analysis_image.insert(tkinter.END,"NTFS\n")
                    self.analysis_image.insert(tkinter.END,"First Sector: "+ str(FirstSector)+"\n")
                    self.analysis_image.insert(tkinter.END,"Total Sectors: "+ str(TotalSectors)+"\n")
                elif FileSystemId == 0x0B:
                    self.analysis_image.insert(tkinter.END,"Partition "+str(i + 1)+"\n")
                    self.analysis_image.insert(tkinter.END,"FAT32\n")
                    self.analysis_image.insert(tkinter.END,"First Sector: "+ str(FirstSector)+"\n")
                    self.analysis_image.insert(tkinter.END,"Total Sectors: "+ str(TotalSectors)+"\n")
                else:
                    self.analysis_image.insert(tkinter.END,"out of scope for homework","\n")
                self.analysis_image.insert(tkinter.END,"\n\n")
        self.analysis_image.config(state='disabled')
        self.analysis_hex.config(state='disabled')

    def gpt(self, image_path):
        self.analysis_image.config(state='normal')
        self.analysis_image.delete('1.0', tkinter.END)
        self.analysis_hex.config(state='normal')
        self.analysis_hex.delete('1.0', tkinter.END)
        with open(image_path, "rb") as f:
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
            Offset = 1024
            for i in range(partition_entry_count):
                partition_start_lba = int.from_bytes(partition_entries[i*128 + 32:i*128 + 40], byteorder='little')
                partition_end_lba = int.from_bytes(partition_entries[i*128 + 40:i*128 + 48], byteorder='little')
                partition_type_guid = ' '.join(['{:02X}'.format(b) for b in partition_entries[i*128:i*128+16]])
                unique_partition_guid = ' '.join(['{:02X}'.format(b) for b in partition_entries[i*128+16:i*128+32]])

                self.analysis_image.insert(tkinter.END,"Partition "+ str(i + 1) +"\n")
                self.analysis_image.insert(tkinter.END,f"Partition Type GUID: {partition_type_guid}" +"\n")
                self.analysis_image.insert(tkinter.END,f"Unique Partition GUID: {unique_partition_guid}" +"\n")
  
                self.analysis_hex.insert(tkinter.END,"Partition "+str(i+1)+"\n")
                hex1 = ' '.join(['{:02X}'.format(b) for b in partition_entries[i:i+200]])
                self.analysis_hex.insert(tkinter.END,hex1+"\n\n")
                
                # Determine the file system type
                f.seek(partition_start_lba * 512)
                file_system_data = f.read(512)  # Read the first sector of the partition
                file_system_signature = file_system_data[3:11]


    
                # Detect known file system signatures
                if file_system_signature == b'NTFS    ':
                    self.analysis_image.insert(tkinter.END,"File System: NTFS\n")
                elif file_system_signature == b'FAT32   ':
                    self.analysis_image.insert(tkinter.END,"File System: FAT32\n")
                else:
                    self.analysis_image.insert(tkinter.END,"File System: Unknown\n")


                # Calculate partition size in MB
                partition_size_mb = (partition_end_lba - partition_start_lba + 1) * 512 / 1024 / 1024
                self.analysis_image.insert(tkinter.END,f"Partition Size: {partition_size_mb:.2f} MB\n")

                self.analysis_image.insert(tkinter.END,f"Offset Sector: {hex(Offset)}\n\n")
                Offset += 32
                
        self.analysis_image.config(state='disabled')
        self.analysis_hex.config(state='disabled')


if __name__ == '__main__':
    MbrVbr()
