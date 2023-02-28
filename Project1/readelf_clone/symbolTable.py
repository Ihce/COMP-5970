import struct
from readelf_clone.sectionHeader import *
from readelf_clone.lookupDictionary.lookupDictionary import stDictionary
BYTE = 1
HALFWORD = 2
WORD = 4
DOUBLEWORD = 8

class SymbolTable():
    # Initializes the program header object with attributes that are usable to create entries
    def __init__(self, elf, ei_class, sectionEntries, index_symbol_table, index_symbol_string_table, e_shstrndx, e_shentsize) -> None:
        self.elf = elf
        self.ei_class = ei_class
        self.sectionEntries = sectionEntries
        # The index of the symbol table in the list of sections
        self.index_symbol_table = index_symbol_table
        # The index of the string table in the list of section that corresponds to the symbol table
        self.index_symbol_string_table = index_symbol_string_table
        self.e_shentsize = e_shentsize
        self.e_shstrndx = e_shstrndx
        self.entries = self.createEntries()

    # Matches the valueKey (typically an attibute of the object) with the corresponding key in the corresponding dictionary
    def safeget(self, attributeKey, valueKey):
        try:
            message = stDictionary[attributeKey][valueKey]
        except KeyError:
            return "Unknown"
        return message

    # Creates and returns a list of entries that can be iterated over
    def createEntries(self):
        entryList = []
        currentOffset = 0
        while currentOffset < self.sectionEntries[self.index_symbol_table].sh_size:
            entryList.append(self.SymbolEntry(self.elf, self.ei_class, self.sectionEntries, self.index_symbol_table, self.index_symbol_string_table, currentOffset, self.e_shstrndx, self.e_shentsize))
            if self.ei_class == 1:
                currentOffset += 16
            else:
                currentOffset += 24
        return entryList
    
    # Iterates over the list of entries and returns the results from their respective fields.
    # Source: Visually inspecting readelf results
    def getSymbolTable(self):
        number = 0
        print('\t%-5s %-8s %-6s %-8s %-8s %-10s %-6s %-8s' %('Num:', 'Value', 'Size', 'Type', 'Bind', 'Vis', 'Ndx', 'Name'))
        for entry in self.entries:
            print('\t%-5s %-8s %-6s %-8s %-8s %-10s %-6s %-8s' 
                    %(
                        number,
                        "{:06x}".format(entry.st_value),
                        entry.st_size,
                        self.safeget('stType', entry.st_type),
                        self.safeget('stBind', entry.st_bind),
                        self.safeget('stVisibility', entry.st_vis),
                        entry.st_shndx,
                        entry.st_converted_name
                    )
            
            )
            number = number + 1

    class SymbolEntry():
        # Initializes a section header entry and unpacks the bytes sequentially with the corresponding size from documention
        # Source: 
        #    https://refspecs.linuxbase.org/elf/gabi4+/
        #    https://wiki.osdev.org/ELF_Tutorial
        #    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
        #    https://man7.org/linux/man-pages/man5/elf.5.html
        def __init__(self, elf, ei_class, sectionEntries, index_table, index_string_table, currentOffset, e_shstrndx, e_shentsize) -> None:
            self.elf = elf
            self.ei_class = ei_class
            self.sectionEntries = sectionEntries
            self.index_tale = index_table
            self.index_string_table = index_string_table
            self.e_shstrndx = e_shstrndx
            self.e_shentsize = e_shentsize
            elf.seek(self.sectionEntries[index_table].sh_offset + currentOffset)
            if self.ei_class == 1:
                self.st_name = struct.unpack('I', self.elf.read(WORD))[0]
                self.st_value = struct.unpack('I', self.elf.read(WORD))[0]
                self.st_size = struct.unpack('I', self.elf.read(WORD))[0]
                self.st_info = struct.unpack('B', self.elf.read(BYTE))[0]
                self.st_other = struct.unpack('B', self. elf.read(BYTE))[0]
                self.st_shndx = struct.unpack('H', self.elf.read(HALFWORD))[0]
            else:
                self.st_name = struct.unpack('I', self.elf.read(WORD))[0]
                self.st_info = struct.unpack('B', self.elf.read(BYTE))[0]
                self.st_other = struct.unpack('B', self.elf.read(BYTE))[0]
                self.st_shndx = struct.unpack('H', self. elf.read(HALFWORD))[0]
                self.st_value = struct.unpack('Q', self.elf.read(DOUBLEWORD))[0]
                self.st_size = struct.unpack('Q', self.elf.read(DOUBLEWORD))[0]

            self.st_type = self.st_info & 15
            self.st_bind = self.st_info >> 4
            self.st_vis = self.st_other & 3
            if self.st_name == 0 and self.st_type == 3:
                self.st_converted_name = self.getSHStringTable(self.sectionEntries[self.st_shndx].sh_name)
            else:
                self.st_converted_name = self.getSTStringTable(self.st_name, self.index_string_table)

         # Returns the corresponding string for the name offset in the string table
        def getSTStringTable(self, nameOffset, index_string_table):
            stringSectionObject = self.sectionEntries[index_string_table]
            self.elf.seek(stringSectionObject.sh_offset + nameOffset)
            data = self.elf.read(stringSectionObject.sh_size)
            output = data.split(b"\x00")[0].decode()
            if output == '':
                return 'NULL'
            return output
        
        # Returns the corresponding string for the name offset in the section header string table
        def getSHStringTable(self, sh_name):
            stringSectionObject = self.sectionEntries[self.e_shstrndx]
            self.elf.seek(stringSectionObject.sh_offset + sh_name)
            data = self.elf.read(self.e_shentsize)
            output = data.split(b"\x00")[0].decode()
            if output == '':
                return 'NULL'
            return output
