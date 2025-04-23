module Api
  module V1
    class AuthenticationController < ApplicationController
      skip_before_action :authenticate_request!, only: [:login]
      before_action :authenticate_request!, only: [:refresh, :logout]

      def login
        user = User.find_by(email: params[:email])
        if user&.authenticate(params[:password])
          token = JsonWebToken.encode(id: user.id, jwt_version: user.jwt_version)
          render json: {
            token: token,
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
              role: user.role.name
            }
          }, status: :ok
        else
          render json: { error: 'Invalid credentials' }, status: :unauthorized
        end
      end

      def refresh
        token = JsonWebToken.encode(id: @current_user.id, jwt_version: @current_user.jwt_version)
        render json: { token: token }, status: :ok
      end

      def logout
        @current_user.update(jwt_version: SecureRandom.uuid)
        render json: { message: 'Logged out successfully' }, status: :ok
      end
    end
  end
end 