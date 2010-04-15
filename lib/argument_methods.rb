module ArgumentMethods
  def self.included(klass)
    klass.extend ClassMethods
    klass.send(:include, InstanceMethods)
  end

  module ClassMethods
    protected
      def add_argument_methods(name, type) #:nodoc:
        class_eval <<-"end;"
          def #{name}_file_name
            assign_argument_variables!(:#{name}) unless @#{name}_file_path
            @#{name}_file_name
          end

          def #{name}_class_path
            assign_argument_variables!(:#{name}) unless @#{name}_class_path
            @#{name}_class_path
          end

          def #{name}_file_path
            @#{name}_file_path ||= (#{name}_class_path + [#{name}_file_name]).join('/')
          end

          def #{name}_class_name
            @#{name}_class_name ||= (#{name}_class_path + [#{name}_file_name]).map!{ |m| m.camelize }.join('::')
          end

          def #{name}_singular_name
            @#{name}_singular_name ||= #{type == :singular ? "#{name}_file_name" : "#{name}_file_name.singularize"}
          end

          def #{name}_plural_name
            @#{name}_plural_name ||= #{type == :singular ? "#{name}_file_name.pluralize" : "#{name}_file_name"}
          end
        end;
      end
  end

  module InstanceMethods
    protected
      def assign_argument_variables!(name) #:nodoc:
        value = send(name)
        class_path = value.include?('/') ? value.split('/') : value.split('::')
        class_path.map!{|m| m.underscore }
        instance_variable_set :"@#{name}_file_name", class_path.pop
        instance_variable_set :"@#{name}_class_path", class_path
      end
  end
end
