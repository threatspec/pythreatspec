class Story:
  '''
  Represents a book.

  @alias threat @cwe_319_cleartext_transmission to cleartext \
  transmission of data
  @describe threat @cwe_319_cleartext_transmission as The software transmits sensitive or \
    security-critical data in cleartext in a communication channel that can be sniffed by \
    unauthorized actors
  @alias boundary @webapp to WebApp
  @describe boundary @webapp as Customer facing web application
  @mitigates @webapp:FileSystem against unauthorised access with strict \
    file permissions (#123)
  @exposes @webapp:App to XSS injection with insufficient input validation. (#567)
  @transfers @cwe_319_cleartext_transmission to User:Browser with non-sensitive \
    information
  @accepts arbitrary file writes to @webapp:FileSystem with filename \
    restrictions (#666)
  '''
  def __init__(self, title, author):
      self.title = title
      self.author = author

def do_something(data1, data):
    '''
    @alias threat @cwe_319_cleartext_transmission to cleartext \
    transmission of data
    @describe threat @cwe_319_cleartext_transmission as The software transmits sensitive or \
      security-critical data in cleartext in a communication channel that can be sniffed by \
      unauthorized actors
    @alias boundary @webapp to WebApp
    @describe boundary @webapp as Customer facing web application
    @mitigates @webapp:FileSystem against unauthorised access with strict \
      file permissions (#123)
    @exposes @webapp:App to XSS injection with insufficient input validation. (#567,#123,#41234)
    @transfers @cwe_319_cleartext_transmission to User:Browser with non-sensitive \
      information
    @accepts arbitrary file writes to @webapp:FileSystem with filename \
      restrictions (#666)
    '''
    pass
