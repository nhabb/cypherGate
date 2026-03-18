import numpy as np
import joblib   #save trained models into the disk and load them without retraining 


# ===============================
# Agent Wrapper (File Loader)
# ===============================

class Agent:

    def __init__(self, name, model_path, weight=1.0):
        """
        name       → agent name
        model_path → path to saved model file
        weight     → trust weight
        """

        self.name = name
        self.weight = weight
        self.model = self.load_model(model_path)

    # ---------- Model Loader ----------

    def load_model(self, path):
        try:
            return joblib.load(path)
        except Exception as e:
            raise RuntimeError(f"Failed loading {self.name}: {e}")

    # ---------- Prediction Interface ----------

    def predict_proba(self, sample):
        return self.model.predict_proba(sample)[0]

    def predict(self, sample):
        return int(np.argmax(self.predict_proba(sample)))


# ===============================
# Multi-Agent Board Controller
# ===============================

class MultiAgentBoard:

    def __init__(self, agents):

        self.agents = agents

        # Normalize weights
        total_weight = sum(a.weight for a in agents)

        if total_weight == 0:
            raise ValueError("Total board weights cannot be zero")

        for agent in self.agents:
            agent.weight /= total_weight

    # ---------- Decision Fusion ----------

    def decide(self, sample):

        fused_score = None
        votes = []

        for agent in self.agents:

            probs = agent.predict_proba(sample)
            weighted_probs = agent.weight * np.array(probs)

            votes.append(agent.predict(sample))

            if fused_score is None:
                fused_score = weighted_probs
            else:
                fused_score += weighted_probs

        return {
            "votes": votes,
            "final_decision": int(np.argmax(fused_score)),
            "fused_score": fused_score
        }


# ===============================
# Example Usage
# ===============================

if __name__ == "__main__":

    agent1 = Agent(
        name="HF_Backbone",
        model_path="hf_model.pkl",
        weight=0.5
    )

    agent2 = Agent(
        name="Learner_A",
        model_path="agent1.pkl",
        weight=0.25
    )

    agent3 = Agent(
        name="Learner_B",
        model_path="agent2.pkl",
        weight=0.25
    )

    board = MultiAgentBoard([agent1, agent2, agent3])

    sample = np.zeros((1, 10))   # Replace with real feature vector

    result = board.decide(sample)

    print("Board Decision:", result["final_decision"])