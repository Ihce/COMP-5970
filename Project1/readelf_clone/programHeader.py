import struct
BYTE = 1
HALFWORD = 2
WORD = 4
DOUBLEWORD = 8
from readelf_clone.lookupDictionary.lookupDictionary import phDictionary

class ProgramHeader():
    # Initializes the program header object with attributes that are usable to create entries
    def __init__(self, elf, arch, phOffset, phNum) -> None:
        self.elf = elf
        self.arch = arch
        self.phOffset = phOffset
        self.phNum = phNum
        self.entries = self.createEntries()

    # Matches the valueKey (typically an attibute of the object) with the corresponding key in the corresponding dictionary
    def safeget(self, attributeKey, valueKey):
        try:
            message = phDictionary[attributeKey][valueKey]
        except KeyError:
            return "Unknown"
        return message   
    
    # Creates the number of entry object specified by the elf header while keeping track of the offset
    def createEntries(self):
        num = self.phNum
        entryList = []
        currentOffset = self.phOffset
        for _ in range(0, num):
            entryList.append(self.ProgramHeaderEntry(self.elf, currentOffset, self.arch))
            if self.arch == 1:
                currentOffset = currentOffset + 32
            else:
                currentOffset = currentOffset + 56
        return entryList     

    # Prints the stored attributes in the header object and returns them in a similar format to the readelf command.
    # Source: Visually inspecting readelf results
    def getEntries(self):
        print('\t%-15s %-10s %-10s %-10s %-10s %-10s %-5s %s' %('Type', 'Offset', 'VirtAddr', 'PhysAddr', 'FileSiz', 'memSiz', 'Flg', 'Align'))
        for element in self.entries:
            print('\t%-15s %-10s %-10s %-10s %-10s %-10s %-5s %s' 
                  %(self.safeget('Type',element.p_type), 
                  "0x{:06x}".format(element.p_offset), 
                  "0x{:06x}".format(element.p_vaddr), 
                  "0x{:06x}".format(element.p_paddr), 
                  "0x{:06x}".format(element.p_filesz), 
                  "0x{:06x}".format(element.p_memsz), 
                  self.safeget('Flag',element.p_flags), 
                  "0x{:x}".format(element.p_align)))
            
    class ProgramHeaderEntry():
        # Initializes a program header entry and unpacks the bytes sequentially with the corresponding size from documention
        # Source: 
        #    https://refspecs.linuxbase.org/elf/gabi4+/
        #    https://wiki.osdev.org/ELF_Tutorial
        #    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
        #    https://man7.org/linux/man-pages/man5/elf.5.html
        def __init__(self, elf, offset, arch) -> None:
            elf.seek(offset)
            if arch == 1:
                self.p_type   = struct.unpack('I', elf.read(WORD))[0]
                self.p_offset = struct.unpack('I', elf.read(WORD))[0]
                self.p_vaddr  = struct.unpack('I', elf.read(WORD))[0]
                self.p_paddr  = struct.unpack('I', elf.read(WORD))[0]
                self.p_filesz = struct.unpack('I', elf.read(WORD))[0]
                self.p_memsz  = struct.unpack('I', elf.read(WORD))[0]
                self.p_flags  = struct.unpack('I', elf.read(WORD))[0]
                self.p_align  = struct.unpack('I', elf.read(WORD))[0]
            else:
                self.p_type = struct.unpack('I', elf.read(WORD))[0]
                self.p_flags = struct.unpack('I', elf.read(WORD))[0]
                self.p_offset = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.p_vaddr = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.p_paddr = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.p_filesz = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.p_memsz = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.p_align = struct.unpack('Q', elf.read(DOUBLEWORD))[0]