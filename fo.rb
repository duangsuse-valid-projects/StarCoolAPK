class Interface
  attr_accessor :name, :method, :path, :args, :type
  def initialize(json)
    @method = json['method']
    @path = json['path_template']
    @name = json['fun']['name']
    @args = json['fun']['args']
    @type = json['fun']['type']
  end

  def codegen_method; return method == 'GET' ? '' : "#{method}@" end
  def codegen_type_name; case type['name'] when 'List' then 'array' end; end
  def codegen_type
    if type.is_a?(String) then "-> #{type}" else "-> #{codegen_type_name}:#{type['inner']}" end
  end
  def codegen_args
    args.map do |a|
      web_param = a['name']
      param = a['param']
      type = a['type']
      case a['ann']
        when 'Query' then "#{web_param}:#{type}"
        when 'Body' then "#{web_param}:#{type}-body"
      end
    end.join(', ')
  end
  def codegen_name; path.match(/(.*)\/(.*)/).yield_self { |md| "#{md[1]}#{md[2].capitalize}" }; end

  def codegen
    "#{codegen_method}#{codegen_name}(#{codegen_args})#{codegen_type}\n  = #{path}"
  end
end 
