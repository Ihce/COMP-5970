from readelf_clone.elfHeader import *
from readelf_clone.programHeader import *
from readelf_clone.sectionHeader import *
from readelf_clone.symbolTable import *

class Elf:
    def __init__(self, elf) -> None:
        self.header = Header(elf)
        self.programHeader = ProgramHeader( 
            elf, 
            self.header.getArchitecture(), 
            self.header.getProgramHeaderOffset(), 
            self.header.getProgramHeaderNumber()
        )
        self.sectionHeader = SectionHeader( 
            elf, 
            self.header.getArchitecture(), 
            self.header.getSectionHeaderOffset(), 
            self.header.getSectionHeaderSize(), 
            self.header.getSectionHeaderNumber(),
            self.header.getStringTableIndex()
        )
        if self.sectionHeader.indexSYMTAB != -1:
            self.symbolTable = SymbolTable(
                elf,
                self.header.getArchitecture(),
                self.sectionHeader.entries,
                self.sectionHeader.indexSYMTAB,
                self.sectionHeader.indexSTRTAB,
                self.header.getStringTableIndex(),
                self.header.getSectionHeaderSize()
            )
        else:
            print('There is no symbol table')
        if self.sectionHeader.indexDYNSYM != -1:
            self.dynamicSymbolTable = SymbolTable(
                elf,
                self.header.getArchitecture(),
                self.sectionHeader.entries,
                self.sectionHeader.indexDYNSYM,
                self.sectionHeader.indexDYNSTR,
                self.header.getStringTableIndex(),
                self.header.getSectionHeaderSize()
            )
        else:
            print('There is no dynamic symbol table')







                
            


        


