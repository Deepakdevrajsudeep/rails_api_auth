class ApplicationController < ActionController::API
  
  # private

  # def authenticate_request
  #   header = request.headers['Authorization']
  #   token = header.split(' ').last if header
  #   begin
  #     decoded_token = JWT.decode(token, Rails.application.secrets.secret_key_base)
  #     @current_user = User.find(decoded_token.first['user_id'])
  #   rescue JWT::DecodeError
  #     render json: { error: 'Invalid token' }, status: :unauthorized
  #   end
  # end
end
