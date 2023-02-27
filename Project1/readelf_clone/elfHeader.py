import struct
from readelf_clone.lookupDictionary.lookupDictionary import hDictionary
BYTE = 1
HALFWORD = 2
WORD = 4
DOUBLEWORD = 8

class Header:
    # Initializes the header object and unpacks the bytes sequentially with the corresponding size from documention.
    # Source: 
    #    https://refspecs.linuxbase.org/elf/gabi4+/
    #    https://wiki.osdev.org/ELF_Tutorial
    #    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    #    https://man7.org/linux/man-pages/man5/elf.5.html
    def __init__(self, elf) -> None:
        self.e_ident = {
            'ei_mag0': struct.unpack('B', elf.read(BYTE))[0],
            'ei_mag1': struct.unpack('B', elf.read(BYTE))[0],
            'ei_mag2':	struct.unpack('B', elf.read(BYTE))[0],
            'ei_mag3':	struct.unpack('B', elf.read(BYTE))[0],
            'ei_class': struct.unpack('B', elf.read(BYTE))[0],
            'ei_data': struct.unpack('B', elf.read(BYTE))[0],
            'ei_version': struct.unpack('B', elf.read(BYTE))[0],
            'ei_osabi': struct.unpack('B', elf.read(BYTE))[0],	
            'ei_abiversion': struct.unpack('B', elf.read(BYTE))[0],
            'ei_pad': struct.unpack('7B', elf.read(7))[0],
        }
        self.e_type = struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_machine = struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_version = struct.unpack('I', elf.read(WORD))[0]
       
        if self.e_ident["ei_class"] == 2:
            self.e_entry= struct.unpack('Q', elf.read(DOUBLEWORD))[0]
            self.e_phoff= struct.unpack('Q', elf.read(DOUBLEWORD))[0]
            self.e_shoff= struct.unpack('Q', elf.read(DOUBLEWORD))[0]
        else: 
            self.e_entry= struct.unpack('I', elf.read(WORD))[0]
            self.e_phoff= struct.unpack('I', elf.read(WORD))[0]
            self.e_shoff= struct.unpack('I', elf.read(WORD))[0]

        self.e_flags= struct.unpack('I', elf.read(WORD))[0]
        self.e_ehsize= struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_phentsize= struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_phnum= struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_shentsize= struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_shnum = struct.unpack('H', elf.read(HALFWORD))[0]
        self.e_shstrndx= struct.unpack('H', elf.read(HALFWORD))[0]

        # Raises and exception and exits if the file is not an ELF
        identifier = format(self.e_ident['ei_mag0'], 'x') + format(self.e_ident['ei_mag1'], 'x') + format(self.e_ident['ei_mag2'], 'x') + format(self.e_ident['ei_mag3'], 'x')
        if identifier != '7f454c46':
            raise Exception('This is not an ELF file')
    
    # Prints the stored attributes in the header object and returns them in a similar format to the readelf command.
    # Source: Visually inspecting readelf results
    def getHeader(self):
        outputDict = {
            "Magic: ": self.getMagic(),
            "Class: ": str(self.safeget('Class', self.e_ident['ei_class'])),
            "Data: ": str(self.safeget('Data', self.e_ident['ei_data'])),
            "Version: ": str(self.safeget('Version', self.e_ident['ei_version'])),
            "OS/ABI: ": str(self.safeget('OS/ABI', self.e_ident['ei_osabi'])),
            "ABI Version: ": str(self.e_ident['ei_abiversion']),
            "Type: ": str(self.safeget('Type', self.e_type)),
            "Machine: ": str(self.safeget('Machine', self.e_machine)),
            "Version: ": str(self.e_version),
            "Entry Point: ": str(hex(self.e_entry)),
            "Entry Point For Program Headers: ": str(self.e_phoff),
            "Entry Point For Section Headers: ": str(self.e_shoff),
            "Flags: ": str(hex(self.e_flags)),
            "Size Of Header: ": str(self.e_ehsize),
            "Size of Program Headers: ": str(self.e_phentsize),
            "Number Of Program Headers: ": str(f"{self.e_phnum:02d}"),
            "Size Of Section Headers: ": str(self.e_shentsize),
            "Number of Section Headers: " : str(self.e_shnum),
            "Section Header String Table Index: ": str(self.e_shstrndx),
        }

        for key,value in outputDict.items():
            print('\t%-36s %-30s' %(key, value))
            
    # Matches the valueKey (typically an attibute of the object) with the corresponding key in the corresponding dictionary
    def safeget(self, attributeKey, valueKey):
        try:
            message = hDictionary[attributeKey][valueKey]
        except KeyError:
                return "Unknown"
        return message
    
    # The following get methods provides vital fields from the header for other classes in the program

    def getMagic(self):
        magic = ''.join(str(format(self.e_ident[item], '02x') + " ") for item in self.e_ident) + "00 "*6
        return magic
    
    def getProgramHeaderOffset(self):
        return self.e_phoff

    def getProgramHeaderSize(self):
        return self.e_phentsize

    def getProgramHeaderNumber(self):
        return self.e_phnum

    def getSectionHeaderOffset(self):
        return self.e_shoff

    def getSectionHeaderSize(self):
        return self.e_shentsize

    def getSectionHeaderNumber(self):
        return self.e_shnum

    def getArchitecture(self):
        return self.e_ident['ei_class']

    def getStringTableIndex(self):
        return self.e_shstrndx