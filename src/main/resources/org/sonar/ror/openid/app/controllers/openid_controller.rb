class OpenidController < ApplicationController

  def validate
    begin
      self.current_user = User.authenticate(nil, nil, servlet_request)

    rescue Exception => e
      puts e
      self.current_user = nil
    end
    redirect_back_or_default(home_url)
  end

end
