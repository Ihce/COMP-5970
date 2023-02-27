import struct
from readelf_clone.lookupDictionary.lookupDictionary import shDictionary
BYTE = 1
HALFWORD = 2
WORD = 4
DOUBLEWORD = 8

class SectionHeader():
    def __init__(self, elf, ei_class, e_shoff, e_shentsize, e_shnum, e_shstrndx) -> None:
        self.elf = elf
        self.ei_class = ei_class
        self.e_shoff = e_shoff
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx
        self.entries = self.createSections()
        
        for count, element in enumerate(self.entries):
            if self.getSHStringTable(element.sh_name) == '.symtab':
                self.indexSYMTAB = count
            if self.getSHStringTable(element.sh_name) == '.strtab':
                self.indexSTRTAB = count  
            if self.getSHStringTable(element.sh_name) == '.dynsym':
                self.indexDYNSYM = count
            if self.getSHStringTable(element.sh_name) == '.dynstr':
                self.indexDYNSTR = count

    def safeget(self, attributeKey, valueKey):
        try:
            message = shDictionary[attributeKey][valueKey]
        except KeyError:
            return "Unknown"
        return message
    
    def getSHStringTable(self, sh_name):
        stringSectionObject = self.entries[self.e_shstrndx]
        self.elf.seek(stringSectionObject.sh_offset + sh_name)
        data = self.elf.read(self.e_shentsize)
        output = data.split(b"\x00")[0].decode()
        if output == '':
            return 'NULL'
        return output
    
    def createSections(self):
        num = self.e_shnum
        entryList = []
        currentOffset = self.e_shoff
        for _ in range(0, num):
            entryList.append(self.SectionHeaderEntry(self.elf, currentOffset, self.ei_class, self.e_shentsize))
            if self.ei_class == 1:
                currentOffset = currentOffset + 40
            else:
                currentOffset = currentOffset + 64
        return entryList
    
    def getSections(self):
        print('%-5s %-16s %-13s %-8s %-8s %-8s %-4s %-6s %-4s %-5s %-6s' %('[Nr]', 'Name', 'Type', 'Addr', 'Off', 'Size', 'ES', 'Flag', 'Lk', 'Inf', 'Al'))
        for index,entry in enumerate(self.entries):
            number = '[%s]'%(index)
            converted_flags = ''
            for key, value in shDictionary['Flags'].items():
                if entry.sh_flags & key or entry.sh_flags == key:
                    converted_flags += value
            print('%-5s %-16s %-13s %-8s %-8s %-8s %-4s %-6s %-4s %-5s %-6s' 
                  %(
                    number, 
                    self.getSHStringTable(entry.sh_name), 
                    self.safeget('Type',entry.sh_type), 
                    "{:06x}".format(entry.sh_addr), 
                    "{:06x}".format(entry.sh_offset), 
                    "{:06x}".format(entry.sh_size), 
                    "{:02x}".format(entry.sh_entsize),
                    converted_flags,
                    entry.sh_link, 
                    entry.sh_info, 
                    entry.sh_addralign))
            
    class SectionHeaderEntry():
        def __init__(self, elf, offset, arch, e_shentsize) -> None:
            elf.seek(offset)
            if arch == 1:
                self.sh_name   = struct.unpack('I', elf.read(WORD))[0]
                self.sh_type = struct.unpack('I', elf.read(WORD))[0]
                self.sh_flags  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_addr  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_offset = struct.unpack('I', elf.read(WORD))[0]
                self.sh_size  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_link  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_info  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_addralign  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_entsize  = struct.unpack('I', elf.read(WORD))[0] 
            else:
                self.sh_name   = struct.unpack('I', elf.read(WORD))[0]
                self.sh_type = struct.unpack('I', elf.read(WORD))[0]
                self.sh_flags  = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.sh_addr  = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.sh_offset = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.sh_size  = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.sh_link  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_info  = struct.unpack('I', elf.read(WORD))[0]
                self.sh_addralign  = struct.unpack('Q', elf.read(DOUBLEWORD))[0]
                self.sh_entsize  = struct.unpack('Q', elf.read(DOUBLEWORD))[0]