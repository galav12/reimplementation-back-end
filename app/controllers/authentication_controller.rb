# app/controllers/api/v1/authentication_controller.rb
require 'json_web_token'

class AuthenticationController < ApplicationController
  skip_before_action :authenticate_request!
  
  # Simple in-memory rate limiting
  LOGIN_ATTEMPTS = {}
  MAX_ATTEMPTS = 5
  BLOCK_DURATION = 20.seconds

  # POST /login
  def login
    # Add a small random delay to prevent timing attacks
    sleep(rand(0.1..0.3))
    
    # Check rate limiting
    ip = request.remote_ip
    username = params[:user_name].to_s.downcase
    
    # Skip rate limiting for localhost
    is_localhost = ip == '127.0.0.1' || ip == '::1'
    
    unless is_localhost
      # Check if IP is blocked
      if LOGIN_ATTEMPTS[ip] && LOGIN_ATTEMPTS[ip][:count] >= MAX_ATTEMPTS && 
         Time.now - LOGIN_ATTEMPTS[ip][:timestamp] < BLOCK_DURATION
        render json: { error: 'Rate limit exceeded. Try again later.' }, status: :too_many_requests
        return
      end
      
      # Check if username is blocked
      if LOGIN_ATTEMPTS[username] && LOGIN_ATTEMPTS[username][:count] >= MAX_ATTEMPTS && 
         Time.now - LOGIN_ATTEMPTS[username][:timestamp] < BLOCK_DURATION
        render json: { error: 'Rate limit exceeded. Try again later.' }, status: :too_many_requests
        return
      end
    end
    
    user = User.find_by(email: params[:email])
    
    if user&.authenticate(params[:password])
      # Reset counters on successful login
      LOGIN_ATTEMPTS[ip] = { count: 0, timestamp: Time.now } if LOGIN_ATTEMPTS[ip]
      LOGIN_ATTEMPTS[username] = { count: 0, timestamp: Time.now } if LOGIN_ATTEMPTS[username]
      
      token = JsonWebToken.encode(
        id: user.id, 
        jwt_version: user.jwt_version,
        exp: 24.hours.from_now.to_i  # Add expiration
      )
      refresh_token = JsonWebToken.encode(
        id: user.id,
        exp: 7.days.from_now.to_i
      )
      render json: {
        token: token,
        refresh_token: refresh_token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name
        }
      }, status: :ok
    else
      # Only increment counters for non-localhost requests
      unless is_localhost
        # Increment counters on failed login
        LOGIN_ATTEMPTS[ip] ||= { count: 0, timestamp: Time.now }
        LOGIN_ATTEMPTS[ip][:count] += 1
        LOGIN_ATTEMPTS[ip][:timestamp] = Time.now
        
        LOGIN_ATTEMPTS[username] ||= { count: 0, timestamp: Time.now }
        LOGIN_ATTEMPTS[username][:count] += 1
        LOGIN_ATTEMPTS[username][:timestamp] = Time.now
        
        # Check if we've exceeded the rate limit after this failed attempt
        if LOGIN_ATTEMPTS[ip][:count] > MAX_ATTEMPTS || LOGIN_ATTEMPTS[username][:count] > MAX_ATTEMPTS
          render json: { error: 'Rate limit exceeded. Try again later.' }, status: :too_many_requests
          return
        end
      end
      
      # Use a generic error message that doesn't reveal whether the username exists
      render json: { error: 'Invalid credentials' }, status: :unauthorized
    end
  end
end
