def find_by_with_replica_fallback(*args)
        Semgrep::Services::ActiveRecord.with_statement_timeout(self, ms: 100) 
    do
        begin
            return false, self.find_by(*args)
        rescue ActiveRecord::ActiveRecordError
            # fallback to primary
        end
        end

        Semgrep::Services::ActiveRecord.using_replica do
        return true, self.on_replica.find_by(*args)
        end
    end

    def cached(cache_field, field_value)
        unless CACHEABLE_TABLES.include?(self.name)
        raise StandardError.new("Unsupported table for caching: #{self.name}")
        end
