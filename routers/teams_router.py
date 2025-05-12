"""
# /home/ubuntu/flowvault_backend_fastapi/routers/teams_router.py

import uuid
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
import logging

# Placeholder for database connection/session and authentication dependency
# from ..dependencies import get_db_session, get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/teams",
    tags=["teams"],
    # dependencies=[Depends(get_current_active_user)], # Add auth dependency later
)

# Mock database for teams (replace with actual DB interaction)
MOCK_DB_TEAMS = {
    "t1": {"team_id": "t1", "name": "Acme Design Team", "owner_user_id": "user123"},
    "t2": {"team_id": "t2", "name": "Startup X - Product Team", "owner_user_id": "user456"},
}
MOCK_DB_TEAM_MEMBERS = {
    ("t1", "user123"): {"team_id": "t1", "user_id": "user123", "role": "owner"},
    ("t1", "user789"): {"team_id": "t1", "user_id": "user789", "role": "member"},
    ("t2", "user456"): {"team_id": "t2", "user_id": "user456", "role": "owner"},
}

class TeamBase(BaseModel):
    name: str

class TeamCreate(TeamBase):
    pass

class TeamUpdate(TeamBase):
    name: Optional[str] = None
    owner_user_id: Optional[str] = None # For transferring ownership

class TeamResponse(TeamBase):
    team_id: str
    owner_user_id: str
    # member_count: int # Will be calculated or joined
    # collections_count: int # Will be calculated or joined

class TeamMember(BaseModel):
    user_id: str
    role: str # e.g., "owner", "admin", "member"

@router.post("/", response_model=TeamResponse, status_code=201)
async def create_team(team: TeamCreate):
    # user = Depends(get_current_active_user)
    # owner_user_id = user.id
    owner_user_id = "user123" # Mock owner
    team_id = str(uuid.uuid4())
    
    new_team_data = team.model_dump()
    new_team_data["team_id"] = team_id
    new_team_data["owner_user_id"] = owner_user_id
    
MOCK_DB_TEAMS[team_id] = new_team_data
    # Add owner as the first member
MOCK_DB_TEAM_MEMBERS[(team_id, owner_user_id)] = {"team_id": team_id, "user_id": owner_user_id, "role": "owner"}
    logger.info(f"User {owner_user_id} created team {team_id} with name {team.name}")
    return new_team_data

@router.get("/", response_model=List[TeamResponse])
async def get_user_teams():
    # user = Depends(get_current_active_user)
    # user_id = user.id
    user_id = "user123" # Mock user_id
    # This should fetch teams where the user is a member
    user_teams_ids = {tm["team_id"] for tm in MOCK_DB_TEAM_MEMBERS.values() if tm["user_id"] == user_id}
    user_teams_data = [team for team_id, team in MOCK_DB_TEAMS.items() if team_id in user_teams_ids]
    return user_teams_data

@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(team_id: str):
    # user = Depends(get_current_active_user)
    # user_id = user.id
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    team_data = MOCK_DB_TEAMS[team_id]
    # Add permission check: user must be a member of the team
    return team_data

@router.put("/{team_id}", response_model=TeamResponse)
async def update_team(team_id: str, team_update: TeamUpdate):
    # user = Depends(get_current_active_user)
    # user_id = user.id
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    
    # Add permission check: user must be owner or admin of the team
    stored_team_data = MOCK_DB_TEAMS[team_id]
    update_data = team_update.model_dump(exclude_unset=True)
    updated_team = stored_team_data.copy()
    updated_team.update(update_data)
    MOCK_DB_TEAMS[team_id] = updated_team
    logger.info(f"Team {team_id} updated.")
    return updated_team

@router.delete("/{team_id}", status_code=204)
async def delete_team(team_id: str):
    # user = Depends(get_current_active_user)
    # user_id = user.id
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    # Add permission check: user must be owner of the team
    del MOCK_DB_TEAMS[team_id]
    # Also remove members and associated team collections (or handle as per business logic)
    keys_to_delete = [key for key in MOCK_DB_TEAM_MEMBERS if key[0] == team_id]
    for key in keys_to_delete:
        del MOCK_DB_TEAM_MEMBERS[key]
    logger.info(f"Team {team_id} deleted.")
    return

# --- Team Member Management --- #

@router.post("/{team_id}/members", response_model=TeamMember, status_code=201)
async def add_team_member(team_id: str, member_data: TeamMember):
    # user = Depends(get_current_active_user) # User performing the action
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    # Add permission check: current user must be owner or admin of the team
    # Check if user_to_add exists (mocked for now)
    user_to_add_id = member_data.user_id
    if (team_id, user_to_add_id) in MOCK_DB_TEAM_MEMBERS:
        raise HTTPException(status_code=400, detail="User is already a member of this team")
    
MOCK_DB_TEAM_MEMBERS[(team_id, user_to_add_id)] = {"team_id": team_id, "user_id": user_to_add_id, "role": member_data.role}
    logger.info(f"User {user_to_add_id} added to team {team_id} with role {member_data.role}.")
    return member_data

@router.get("/{team_id}/members", response_model=List[TeamMember])
async def get_team_members(team_id: str):
    # user = Depends(get_current_active_user)
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    # Add permission check: current user must be a member of the team
    members = [data for key, data in MOCK_DB_TEAM_MEMBERS.items() if key[0] == team_id]
    return members

@router.put("/{team_id}/members/{member_user_id}", response_model=TeamMember)
async def update_team_member_role(team_id: str, member_user_id: str, role_data: BaseModel): # Pydantic model for role needed
    # user = Depends(get_current_active_user)
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    if (team_id, member_user_id) not in MOCK_DB_TEAM_MEMBERS:
        raise HTTPException(status_code=404, detail="Member not found in this team")
    # Add permission check: current user must be owner or admin
    # new_role = role_data.role # Assuming role_data has a 'role' field
    new_role = "member" # Mock role update
MOCK_DB_TEAM_MEMBERS[(team_id, member_user_id)]["role"] = new_role
    logger.info(f"User {member_user_id}\'s role in team {team_id} updated to {new_role}.")
    return MOCK_DB_TEAM_MEMBERS[(team_id, member_user_id)]

@router.delete("/{team_id}/members/{member_user_id}", status_code=204)
async def remove_team_member(team_id: str, member_user_id: str):
    # user = Depends(get_current_active_user)
    if team_id not in MOCK_DB_TEAMS:
        raise HTTPException(status_code=404, detail="Team not found")
    if (team_id, member_user_id) not in MOCK_DB_TEAM_MEMBERS:
        raise HTTPException(status_code=404, detail="Member not found in this team")
    # Add permission check: current user must be owner or admin, or user removing themselves (unless owner)
    # Prevent owner from being removed directly without transferring ownership
    if MOCK_DB_TEAMS[team_id]["owner_user_id"] == member_user_id:
        raise HTTPException(status_code=400, detail="Cannot remove the team owner. Transfer ownership first.")

    del MOCK_DB_TEAM_MEMBERS[(team_id, member_user_id)]
    logger.info(f"User {member_user_id} removed from team {team_id}.")
    return

"""
