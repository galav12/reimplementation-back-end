require 'rails_helper'

RSpec.describe Api::V1::AuthenticationController, type: :request do
  let(:role) { create(:role, :student) }
  let(:institution) { create(:institution) }
  let(:user) { create(:user, password: 'password123', role: role, institution: institution) }

  describe 'POST /api/v1/auth/login' do
    context 'with valid credentials' do
      it 'returns a JWT token' do
        post '/api/v1/auth/login', params: { email: user.email, password: 'password123' }
        expect(response).to have_http_status(:ok)
        expect(JSON.parse(response.body)).to have_key('token')
      end
    end

    context 'with invalid credentials' do
      it 'returns unauthorized status' do
        post '/api/v1/auth/login', params: { email: user.email, password: 'wrong_password' }
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end

  describe 'POST /api/v1/auth/refresh' do
    let(:token) { JsonWebToken.encode(user_id: user.id, jwt_version: user.jwt_version) }

    context 'with valid token' do
      it 'returns a new JWT token' do
        post '/api/v1/auth/refresh', headers: { 'Authorization' => "Bearer #{token}" }
        expect(response).to have_http_status(:ok)
        expect(JSON.parse(response.body)).to have_key('token')
      end
    end

    context 'with invalid token' do
      it 'returns unauthorized status' do
        post '/api/v1/auth/refresh', headers: { 'Authorization' => 'Bearer invalid_token' }
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end

  describe 'POST /api/v1/auth/logout' do
    let(:token) { JsonWebToken.encode(user_id: user.id, jwt_version: user.jwt_version) }

    context 'with valid token' do
      it 'invalidates the token and returns success message' do
        post '/api/v1/auth/logout', headers: { 'Authorization' => "Bearer #{token}" }
        expect(response).to have_http_status(:ok)
        expect(JSON.parse(response.body)['message']).to eq('Logged out successfully')
        
        # Verify token is invalidated
        post '/api/v1/auth/refresh', headers: { 'Authorization' => "Bearer #{token}" }
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with invalid token' do
      it 'returns unauthorized status' do
        post '/api/v1/auth/logout', headers: { 'Authorization' => 'Bearer invalid_token' }
        expect(response).to have_http_status(:unauthorized)
      end
    end
  end
end 