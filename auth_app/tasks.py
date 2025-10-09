from django.conf import settings
from django.core.mail import send_mail, BadHeaderError


def send_confirmation_mail(saved_account, activation_link):
    """
    Sends an account confirmation email to a new user.

    This function is intended to be run as a background task (e.g., with RQ or Celery)
    to avoid blocking the web server during the registration process.

    Args:
        saved_account (User): The user model instance that was just created.
        activation_link (str): The unique URL for the user to activate their account.

    Raises:
        ValueError: If the subject, message, or from_email are not configured,
                    or if Django's send_mail function encounters a BadHeaderError,
                    indicating a security issue like a header injection attempt.
    """
    subject = 'Confirm your email'
    message = f'Hey {saved_account.username}, please activate your account here: {activation_link}'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient = saved_account.email

    if subject and message and from_email:
        try:
            send_mail(
                subject,
                message,
                from_email,
                [recipient],
            )
        except BadHeaderError:
            # Raise error here; view will handle the response
            raise ValueError('Invalid header found.')
    else:
        raise ValueError('Make sure all fields are entered and valid.')


def send_reset_password_mail(user, reset_link):
    """
    Sends a password reset email to a user.

    This function is designed to be run as a background task to ensure the
    password reset request process is non-blocking.

    Args:
        user (User): The user model instance requesting the password reset.
        reset_link (str): The unique URL for the user to reset their password.

    Raises:
        ValueError: If essential email fields (subject, message, sender) are missing,
                    or if a BadHeaderError occurs during the sending process.
    """
    subject = 'Reset your password'
    message = f'Hey {user.username}, please reset your password here: {reset_link}'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient = user.email

    if subject and message and from_email:
        try:
            send_mail(
                subject,
                message,
                from_email,
                [recipient],
            )
        except BadHeaderError:
            raise ValueError('Invalid header found.')
    else:
        raise ValueError('Make sure all fields are entered and valid.')
