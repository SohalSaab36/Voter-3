import json
import os
import csv
import hashlib
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter import simpledialog


class VotingApp:
    def __init__(self, root):
        self.vote = {}
        self.admin_password_hash = hashlib.sha256(b'admin').hexdigest()
        self.voting_active = True

        self.root = root
        self.root.title("Voting System")
        self.root.geometry("400x550")
        self.root.config(bg="#f0f0f0")

        # Title Label with Styling
        self.title_label = Label(self.root, text="Voting System", font=("Helvetica", 20, "bold"), fg="white", bg="#2c3e50", padx=10, pady=10)
        self.title_label.pack(fill=X)

        # Main Frame for organizing buttons
        self.main_frame = Frame(self.root, bg="#f0f0f0")
        self.main_frame.pack(pady=20)

        # Register Parties button with styling
        self.register_button = Button(self.main_frame, text="Register Parties", command=self.register_parties, font=("Helvetica", 14), bg="#27ae60", fg="white", padx=10, pady=5)
        self.register_button.pack(pady=10, fill=X)

        # Start Voting button with styling
        self.vote_button = Button(self.main_frame, text="Start Voting", command=self.start_voting, font=("Helvetica", 14), bg="#2980b9", fg="white", padx=10, pady=5)
        self.vote_button.pack(pady=10, fill=X)

        # Load Voting Data button with styling
        self.load_button = Button(self.main_frame, text="Load Voting Data", command=self.load_file, font=("Helvetica", 14), bg="#8e44ad", fg="white", padx=10, pady=5)
        self.load_button.pack(pady=10, fill=X)

        # Save Voting Data button with styling
        self.save_button = Button(self.main_frame, text="Save Voting Data", command=self.save_file, font=("Helvetica", 14), bg="#e67e22", fg="white", padx=10, pady=5)
        self.save_button.pack(pady=10, fill=X)

        # Admin Preview button for the admin to view voting results
        self.admin_button = Button(self.main_frame, text="Admin Panel", command=self.admin_preview, font=("Helvetica", 14), bg="#e74c3c", fg="white", padx=10, pady=5)
        self.admin_button.pack(pady=10, fill=X)

        # Label for status updates with styling
        self.status_label = Label(self.root, text="Status: No actions taken yet", font=("Helvetica", 12), bg="#f0f0f0", fg="#2c3e50")
        self.status_label.pack(pady=20)

    def register_parties(self):
        """Method to register parties."""
        if not self.voting_active:
            messagebox.showwarning("Warning", "Voting has ended. You cannot register more parties.")
            return

        self.new_window = Toplevel(self.root)
        self.new_window.title("Register Parties")
        self.new_window.geometry("300x200")
        self.new_window.config(bg="#f0f0f0")

        Label(self.new_window, text="Enter party names (comma-separated):", font=("Helvetica", 12), bg="#f0f0f0").pack(pady=10)
        self.party_input = Entry(self.new_window, width=30, font=("Helvetica", 12))
        self.party_input.pack(pady=5)

        register_button = Button(self.new_window, text="Register", command=self.save_parties, font=("Helvetica", 12), bg="#27ae60", fg="white", padx=5, pady=5)
        register_button.pack(pady=10)

    def save_parties(self):
        """Save registered parties to the vote dictionary."""
        party_names = self.party_input.get().split(',')
        for party in party_names:
            self.vote[party.strip()] = 0
        self.status_label.config(text=f"Parties Registered: {', '.join(self.vote.keys())}")
        self.new_window.destroy()

    def start_voting(self):
        """Initiate voting."""
        if not self.voting_active:
            messagebox.showwarning("Warning", "Voting has ended.")
            return

        if not self.vote:
            messagebox.showerror("Error", "No parties registered. Please register first.")
            return

        self.new_window = Toplevel(self.root)
        self.new_window.title("Vote for a Party")
        self.new_window.geometry("300x300")
        self.new_window.config(bg="#f0f0f0")

        Label(self.new_window, text="Select a party to vote for:", font=("Helvetica", 12), bg="#f0f0f0").pack(pady=10)
        for party in self.vote.keys():
            button = Button(self.new_window, text=party, command=lambda p=party: self.cast_vote(p), font=("Helvetica", 12), bg="#2980b9", fg="white", padx=5, pady=5)
            button.pack(pady=5, fill=X)

        Button(self.new_window, text="Close", command=self.new_window.destroy, font=("Helvetica", 12), bg="#e74c3c", fg="white", padx=5, pady=5).pack(pady=10)

    def cast_vote(self, party_name):
        """Cast a vote for the selected party."""
        self.vote[party_name] += 1
        self.status_label.config(text="Vote cast! Current vote count hidden for admin review.")
        self.new_window.destroy()

    def load_file(self):
        """Load voting data from a JSON file."""
        file_path = filedialog.askopenfilename(title="Open File", filetypes=(("JSON Files", "*.json"),))
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.vote = json.load(f)
                self.status_label.config(text="Data loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file: {e}")

    def save_file(self):
        """Save voting data to a JSON file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=(("JSON Files", "*.json"),))
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.vote, f, indent=4)
                messagebox.showinfo("Success", f"Data saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")

    def admin_preview(self):
        """Prompt for admin password and show admin panel if correct."""
        password = simpledialog.askstring("Admin Login", "Enter Admin Password:", show='*')
        if hashlib.sha256(password.encode()).hexdigest() == self.admin_password_hash:
            self.admin_panel()
        else:
            messagebox.showerror("Error", "Incorrect password!")

    def admin_panel(self):
        """Admin panel with options to view results, reset votes, and end voting."""
        self.admin_window = Toplevel(self.root)
        self.admin_window.title("Admin Panel")
        self.admin_window.geometry("350x350")
        self.admin_window.config(bg="#f0f0f0")

        Label(self.admin_window, text="Admin Actions", font=("Helvetica", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        view_button = Button(self.admin_window, text="View Voting Results", command=self.show_results, font=("Helvetica", 12), bg="#2980b9", fg="white", padx=5, pady=5)
        view_button.pack(pady=10, fill=X)

        reset_button = Button(self.admin_window, text="Reset Votes", command=self.reset_votes, font=("Helvetica", 12), bg="#e67e22", fg="white", padx=5, pady=5)
        reset_button.pack(pady=10, fill=X)

        export_button = Button(self.admin_window, text="Export Results to CSV", command=self.export_to_csv, font=("Helvetica", 12), bg="#27ae60", fg="white", padx=5, pady=5)
        export_button.pack(pady=10, fill=X)

        end_button = Button(self.admin_window, text="End Voting", command=self.end_voting, font=("Helvetica", 12), bg="#e74c3c", fg="white", padx=5, pady=5)
        end_button.pack(pady=10, fill=X)

        Button(self.admin_window, text="Close", command=self.admin_window.destroy, font=("Helvetica", 12), bg="#c0392b", fg="white", padx=5, pady=5).pack(pady=10)

    def show_results(self):
        """Show the voting results if the admin password is correct."""
        result_window = Toplevel(self.root)
        result_window.title("Voting Results")
        result_window.geometry("300x300")
        result_window.config(bg="#f0f0f0")

        Label(result_window, text="Voting Results:", font=("Helvetica", 14, "bold"), bg="#f0f0f0").pack(pady=10)

        for party, votes in self.vote.items():
            result_label = Label(result_window, text=f"{party}: {votes} votes", font=("Helvetica", 12), bg="#f0f0f0")
            result_label.pack(pady=5)

        Button(result_window, text="Close", command=result_window.destroy, font=("Helvetica", 12), bg="#e74c3c", fg="white", padx=5, pady=5).pack(pady=10)

    def reset_votes(self):
        """Reset all votes to zero."""
        for party in self.vote:
            self.vote[party] = 0
        messagebox.showinfo("Success", "All votes have been reset.")

    def export_to_csv(self):
        """Export the voting results to a CSV file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=(("CSV Files", "*.csv"),))
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Party", "Votes"])
                    for party, votes in self.vote.items():
                        writer.writerow([party, votes])
                messagebox.showinfo("Success", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not export to CSV: {e}")

    def end_voting(self):
        """End the voting session and prevent further votes."""
        self.voting_active = False
        messagebox.showinfo("Success", "Voting has been ended. No further votes can be cast.")


if __name__ == "__main__":
    root = Tk()
    app = VotingApp(root)
    root.mainloop()
