Rails.application.routes.draw do
  devise_for :users, controllers: { sessions: 'users/sessions', registrations: 'users/registrations'}

   post '/authentication', to: 'authentication#create'
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
end
