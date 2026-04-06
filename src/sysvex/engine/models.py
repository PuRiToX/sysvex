class Finding:
    def __init__(self, finding_id, title, severity, description,
    evidence=None, recommendation=None, source_module=None):
        self.id = finding_id
        self.title = title
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation
        self.source_module = source_module

    def to_dict(self):
        return self.__dict__
