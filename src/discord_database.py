from CTFd.models import db


class DiscordUser(db.Model):
    __tablename__ = "discorduser"
    __table_args__ = (db.UniqueConstraint("id"), {})

    # Core variables
    id = db.Column(db.BigInteger, primary_key=True, unique=True)  # Discord ID, int64
    # Discord Username 2-32 characters
    username = db.Column(db.String(128), db.ForeignKey("users.name", ondelete="CASCADE"))
    discriminator = db.Column(db.Integer)  # Discriminator ID, 4 digits
    avatar_hash = db.Column(db.String(256))  # Avatar hash, no known limit, 33 from samples
    mfa_enabled = db.Column(db.Boolean)
    verified = db.Column(db.Boolean)
    email = db.Column(db.String(256))

    def __init__(self, **kwargs):
        super(DiscordUser, self).__init__(**kwargs)
