import struct
BYTE = 1
HALFWORD = 2
WORD = 4
DOUBLEWORD = 8
from readelf_clone.lookupDictionary.lookupDictionary import phDictionary

class ProgramHeader():
    def __init__(self, elf, arch, phOffset, phNum) -> None:
        self.elf = elf
        self.arch = arch
        self.phOffset = phOffset
        self.phNum = phNum
        self.entries = self.createEntries()

    def safeget(self, attributeKey, valueKey):
        try:
            message = phDictionary[attributeKey][valueKey]
        except KeyError:
            return "Unknown"
        return message   

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
    
    def getEntries(self):
        print('%-15s %-10s %-10s %-10s %-10s %-10s %-5s %s' %('Type', 'Offset', 'VirtAddr', 'PhysAddr', 'FileSiz', 'memSiz', 'Flg', 'Align'))
        for element in self.entries:
            print('%-15s %-10s %-10s %-10s %-10s %-10s %-5s %s' 
                  %(self.safeget('Type',element.p_type), 
                  "0x{:06x}".format(element.p_offset), 
                  "0x{:06x}".format(element.p_vaddr), 
                  "0x{:06x}".format(element.p_paddr), 
                  "0x{:06x}".format(element.p_filesz), 
                  "0x{:06x}".format(element.p_memsz), 
                  self.safeget('Flag',element.p_flags), 
                  "0x{:x}".format(element.p_align)))
            
    class ProgramHeaderEntry():
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