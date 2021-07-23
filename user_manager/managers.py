from django.contrib.auth.base_user import BaseUserManager
class UserManager(BaseUserManager):
    def create_user(self, username, password):
        if not username:
            raise ValueError('Enter a username')
        user = self.model(username=username,is_suspended = False)
        user.set_password(password)
        user.save(using=self.db)
        return user
    def create_superuser(self, username, password):
        user = self.create_user(
            username=username,
            password=password)
        user.is_admin = True
        user.is_active = True
        
        user.is_superuser = True
        user.is_staff = True
        
        user.save(using=self._db)
        return user