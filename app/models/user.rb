class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

         has_many :friends
  ROLES = %w{super_admin admin manager editior collaborator}

  ROLES.each do |role_name|
    define_method "#{role_name}?"do
      role == role_name
    end
  end
  # def jwt_payload
  #   super
  # end

  # def super_admin?
  #   role == 'super_admin'
  # end

  # def admin?
  #   role == 'admin'
  # end

  # def manager?
  #   role == 'manager'
  # end

  # def editior?
  #   role == 'editior'
  # end

  # def collaborator?
  #   role == 'collaborator'
  # end
end
