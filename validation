'''
References :
    - https://www.filesignatures.net/index.php?search=gif&mode=EXT
    - https://en.wikipedia.org/wiki/List_of_file_signatures
    - https://sceweb.sce.uhcl.edu/abeysekera/itec3831/labs/FILE%20SIGNATURES%20TABLE.pdf
'''

MAGIC_NUMBERS = {
    'jpeg' : {
        'headerSize' : 4,
        'header' : b'\xFF\xD8\xFF\xE0',
        'footerSize' : 2,
        'footer' : b'\xFF\xD9',
        'offset': 0
    },
    'png' : {
        'headerSize' : 8,
        'header' : b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
        'footerSize' : 8,
        'footer' : b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
        'offset': 0
    },
    'gif' : {
        'headerSize' : 4,
        'header' : b'\x47\x49\x46\x38',
        'footerSize' : 1,
        'footer' : b'\x3B',
        'offset': 0
    }
}

def compareMagicAndExtension(fileExtension, fileToCheck):
    '''
        This func compares provided image file extension with file magic numbers in
        bytes header and footer. This basic check is for security purposes, to avoid 
        bad payloads like reverse shells to be uploaded on server.
        
        @fileExtension [str] - File extension to check (jpeg, png, gif, ...).
        @fileTocheck [str] - File path.
        @return [bool] -  Returns True if they match and False if they don't.
    '''
    # Read file bytes
    with open(fileToCheck, 'rb') as file:
        bytesData = file.read()
    
    #Convert jpg/jpe to jpeg (if extension is not exactly 'jpeg')
    if fileExtension == 'jpg':
        fileExtension = 'jpeg'
    elif fileExtension == 'jpe':
        fileExtension = 'jpeg'

    # Get reference magic numbers from dict
    refMagicHeader = MAGIC_NUMBERS[fileExtension]['header']
    refMagicFooter = MAGIC_NUMBERS[fileExtension]['footer']

    # Get magic numbers of passed file
    fileMagicHeader = bytesData[0:MAGIC_NUMBERS[fileExtension]['headerSize']]
    fileMagicFooter = bytesData[-MAGIC_NUMBERS[fileExtension]['footerSize']:]

    if refMagicHeader == fileMagicHeader and refMagicFooter == fileMagicFooter:
        print("it's a match !")
        return True
    else:
        print("it's not a match ...")
        return False
