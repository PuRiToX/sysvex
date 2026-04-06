class Finding:
    def __init__(self, id, title, severity, description, evidence=None, recommendation=None):
        self.id = id
        self.title = title
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self):
        return self.__dict__