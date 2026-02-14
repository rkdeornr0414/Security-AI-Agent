"""Chat session manager with Layer 3 + 4 integration."""

from agent.providers import Provider
from modules.input_guard import validate_input
from modules.safety import validate_output


class ChatSession:
    """Manages conversation history and provider interaction.

    Layer 4 (input validation) runs before sending to the model.
    Layer 3 (output validation) runs before presenting to the user.
    Layer 5 (user as executor) is inherent -- user runs all commands.
    """

    def __init__(self, provider: Provider, config: dict):
        self.provider = provider
        self.max_history = config.get("max_history", 50)
        self.messages: list[dict] = []

    def send(self, user_message: str) -> str:
        """Send a user message and return the validated assistant response."""
        # Layer 4: Input validation
        guard = validate_input(user_message)
        if not guard.safe:
            return guard.message

        self.messages.append({"role": "user", "content": user_message})

        if len(self.messages) > self.max_history * 2:
            self.messages = self.messages[-(self.max_history * 2):]

        response = self.provider.chat(self.messages)

        # Layer 3: Output validation
        try:
            response = validate_output(response)
        except ValueError as e:
            response = str(e)
            # Remove the user message that triggered bad output
            self.messages.pop()
            return response

        self.messages.append({"role": "assistant", "content": response})

        return response

    def clear(self):
        """Clear conversation history."""
        self.messages = []
