class ApplicationController < ActionController::Base
  before_action :authenticate_user
  include Pundit

  after_action :verify_authorized, except: [:index],
    unless: :devise_controller?
  after_action :verify_policy_scoped, only: [:index],
    unless: :devise_controller?
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  rescue_from Pundit::NotAuthorizedError, with: :not_authorized

  private

  def not_authorized
    redirect_to root_path, alert: "You aren't allowed to do that."
  end

  def authenticate_user
    authenticate_with_http_token do |token|
      @current_user = User.find_by(api_key: token)
    end
  end
  
  def new
  end
end
