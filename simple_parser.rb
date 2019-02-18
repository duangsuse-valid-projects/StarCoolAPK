# Simple parser for retrofit.java

# Data dump as json format
require 'json'

## Simple parser helper
# Author: duangsuse
class RetroParser
  attr_accessor :code, :file, :line, :pos, :last_char

  ## Parser parsing error exception
  class ParserError < Exception
    attr_accessor :message, :file, :line, :pos

    def initialize(msg, file, line, pos)
      @message = msg
      @file = file
      @line = line
      @pos = pos
    end

    def to_s; "Error parsing `#{file}' at line #{line}, position #{pos}: #{message}"; end
  end

  def check_eof(smg)
    raise ParserError.new("Unexpected EOF, expecting #{smg}", file, line, pos) if eof?
  end

  def take(num = 10)
    ret = @code.take(num).first
    @pos += ret.size
    @line += ret.count "\n"
    return ret
  end

  def skip(string)
    io = StringIO.new(string)

    while (ch = char)
      expect = io.getc

      unless ch == expect
        break if expect == nil
        raise ParserError.new("Failed to assert skip: expecting '#{expect}' (#{string}) but" +
                            " found '#{ch}' (#{take io.size})", file, line, pos)
      end
    end
    @code.ungetc(ch)
  end

  def regex(regex, split = ' ')
    regex = Regexp.new(regex) unless regex.is_a? Regexp
    buffer = StringIO.new

    until (ch = char) == split
      buffer << ch
    end

    return buffer.string.match(regex)
  end

  def till(*split)
    buffer = StringIO.new
    until split.include?(ch = char)
      buffer << ch
    end
    return buffer.string
  end

  def peek_char
    check_eof '(peek) one char'
    read = @code.getc
    @code.ungetc(read)
    return read
  end

  def char
    check_eof 'one char'
    ch = @code.getc
    @last_char = ch
    @line += 1 if ch == "\n"
    @pos += 1
    return ch
  end

  def char_is(c); char == c; end
  def peek_char_is(c); peek_char == c; end
  def last_char_is(c); last_char == c; end
  def last_is_blank; last_char_is(' '); end

  def eof?; @code.eof?; end
  def nl?; last_char_is("\n"); end

  def skip_blank
    return unless last_char_is(' ')
    while char_is(' '); end
  end

  def until_nl
    char until nl?
  end

  def debug(msg = 'Note, parsing')
    return unless $DEBUG
    last_ch = last_char == "\n" ? 'NEWLINE' : last_char
    warn "#{msg} at line #{line}, pos #{pos}, last char '#{last_ch}'"
  end

  def initialize(code, file = 'anon', line = -1, pos = 0)
    code = StringIO.new(code) if code.is_a? String
    @code = code
    @file = file
    @line = line
    @pos = pos
  end

  def self.main
    warn "RetroParser file #{ARGF.path}"
    begin
      result = self.new(ARGF, ARGF.path).toplevel
    rescue ParserError => e
      warn e
      warn e.backtrace
    end
    puts JSON.pretty_generate(result)
  end
end

# Parser code
class RetroParser
  def interface_fun
    fun = StringIO.new
    while (ch = char) != ';'
     fun.ungetc(ch)
    end

    # Not efficient but fun (
    fun.string = fun.string.reverse

    until_nl; char

    return RetroParser.new(fun, "inline structure interface_fun_code for #{file}", line, pos).interface_fun_code
  end

  def skip_observable
    skip 'Observable'
  end

  def bl
    return unless peek_char_is("\n") or peek_char_is(" ")
    char while peek_char_is("\n") or peek_char_is(" ")
  end

  def java_type
    type_name = StringIO.new
    while (ch = char)
      if ch == '<' or ch == '>' or ch == ' '
        if ch == '<'
          inner = interface_fun_code_result
        end
        char; break
      end
      type_name << ch
    end
    if inner then return { name: type_name.string, inner: inner } else return type_name.string end
  end

  def interface_fun_arg
    bl; skip '@'
    unless %w[B N].include?(peek_char) # @Body @Name
      annotation = till '('
      annotation.strip!
      bl; skip '"'
      name = till '"'; bl
      skip ')'; bl
    end
    type = interface_fun_code_result
    bl
    param = till ',', ')'

    return { ann: annotation, name: name, type: type, param: param }
  end

  def interface_fun_args
    list = []
    bl
    return [] if peek_char_is ')'

    list << interface_fun_arg

    list << interface_fun_arg while last_char_is ','
    return list
  end

  def interface_fun_code_result
    bl; t = java_type; bl
    return t
  end

  # require lookahead
  def interface_fun_code
    result_of = StringIO.new

    bl; skip_observable; bl
    skip '<'; bl; skip 'Result'; bl; skip '<'
    #type = regex(/.+/, '>') # Not good(
    type = interface_fun_code_result
    bl
    name = till '('
    args = interface_fun_args

    { type: type, name: name, args: args }
  end

  def interface
    method = StringIO.new
    path_template = StringIO.new

    while (c = char) != '('
      method << c
    end

    saved = char
    if not last_is_blank and not last_char_is '"'
      path_template << saved # skip blank and "
    end

    skip_blank

    while (c = char) != '"'
      path_template << c
    end

    unless char_is ')'
      skip_blank
    end

    until_nl

    fun = interface_fun
    { method: method.string, path_template: path_template.string, fun: fun }
  end

  def toplevel
    print "At file #{file}: " if $DEBUG
    debug
    until (c = char) == '{' # Skip interface header
      STDERR.print c
    end

    until_nl

    debug 'Start parsing interfaces'

    interfaces = []
    interfaces << interface while char == '@'
    # Ignore closing brace
    debug 'End parsing interfaces'

    interfaces
  end
end

RetroParser.main if $PROGRAM_NAME == __FILE__
