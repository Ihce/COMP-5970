from readelf_clone.elf import Elf
import argparse
def parseElf():
    parser = argparse.ArgumentParser(description='Sample argparse py', usage=msg())
    parser.add_argument("-a", "--all", help="Display all information", action='store_true', required=False)
    parser.add_argument("-H", "--header", help="Display the ELF file header", action='store_true' , required=False)
    parser.add_argument("-S", "--section", help="Display the section headers", action='store_true' , required=False)
    parser.add_argument("-l","--program", help="Displays the program headers", action='store_true' , required=False)
    parser.add_argument("-s", "--symbol", help="Displays the symbol table", action='store_true' , required=False)
    parser.add_argument("-d", "--dynamicsymbol", help="Display the dynamic symbol table", action='store_true', required=False)
    parser.add_argument('filepath')
    args = parser.parse_args()
    
    if not args.filepath:
        parser.print_usage()
        exit()
    
    if not any([args.all, args.header, args.section, args.program, args.symbol, args.dynamicsymbol]):
        args.all = True
    with open(args.filepath, 'rb') as elfFile:
        elf = Elf(elfFile)
        if args.header or args.all:
            print('\nDisplaying the ELF header')
            elf.header.getHeader()
        if args.program or args.all:
            print('\nDisplaying the program headers')
            elf.programHeader.getEntries()
        if args.section or args.all:
            print('\nDisplaying the section headers')
            elf.sectionHeader.getSections()
        if args.symbol or args.all:
            print('\nDisplaying the symbol table')
            elf.symbolTable.getSymbolTable()
        if args.dynamicsymbol or args.all:
            print('\nDisplaying the dynamic symbol table')
            elf.dynamicSymbolTable.getSymbolTable()
def msg(name = None):
    return '''readelf <options> "full path to elf file"
        -a --all              Display all information
        -H --header           Display the ELF file header
        -S --section          Display the section headers
        -l --program          Displays the program headers
        -s --symbol           Displays the symbol table"
        -d --dynamicsymbol    Display the dynamic symbol table
    '''

if __name__ == '__main__':
    parseElf()    