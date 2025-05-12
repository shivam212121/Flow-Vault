"""
# /home/ubuntu/flowvault_backend_fastapi/routers/collections_router.py

import uuid
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
import logging

# Placeholder for database connection/session and authentication dependency
# from ..dependencies import get_db_session, get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/collections",
    tags=["collections"],
    # dependencies=[Depends(get_current_active_user)], # Add auth dependency later
)

# Mock database for collections (replace with actual DB interaction)
MOCK_DB_COLLECTIONS = {
    "c1": {"collection_id": "c1", "user_id": "user123", "team_id": None, "name": "My Favorite Onboarding Flows", "description": "A collection of interesting onboarding flows.", "is_private": True, "swipe_file_ids": ["sf1", "sf2"]},
    "c2": {"collection_id": "c2", "user_id": None, "team_id": "t1", "name": "Project Phoenix - Checkout Inspirations", "description": "Inspiration for Project Phoenix checkout.", "is_private": False, "swipe_file_ids": ["sf3"]},
}
MOCK_DB_SWIPE_FILES_IN_COLLECTION = {
    ("c1", "sf1"): {"collection_id": "c1", "swipe_file_id": "sf1"},
    ("c1", "sf2"): {"collection_id": "c1", "swipe_file_id": "sf2"},
    ("c2", "sf3"): {"collection_id": "c2", "swipe_file_id": "sf3"},
}

class CollectionBase(BaseModel):
    name: str
    description: Optional[str] = None
    is_private: bool = True
    team_id: Optional[str] = None # If it's a team collection

class CollectionCreate(CollectionBase):
    pass

class CollectionUpdate(CollectionBase):
    name: Optional[str] = None
    description: Optional[str] = None
    is_private: Optional[bool] = None

class CollectionResponse(CollectionBase):
    collection_id: str
    user_id: Optional[str] # Creator if personal, null if team
    # swipe_file_count: int # Will be calculated or joined

class AddSwipeFileToCollectionRequest(BaseModel):
    swipe_file_id: str

@router.post("/", response_model=CollectionResponse, status_code=201)
async def create_collection(collection: CollectionCreate):
    # user = Depends(get_current_active_user) # Get current user
    # user_id = user.id
    user_id = "user123" # Mock user_id
    collection_id = str(uuid.uuid4())
    
    if collection.team_id and user_id: # Basic validation: if team_id is present, user_id (owner) should be None for the collection record itself, handled by team ownership
        # Logic to check if user is part of the team and has permission to create collection for the team
        pass

    new_collection_data = collection.model_dump()
    new_collection_data["collection_id"] = collection_id
    if collection.team_id:
        new_collection_data["user_id"] = None # Team collections are not directly owned by a single user in the `collections` table
    else:
        new_collection_data["user_id"] = user_id
    
    MOCK_DB_COLLECTIONS[collection_id] = new_collection_data
    logger.info(f"User {user_id} created collection {collection_id} with name 	{collection.name}")
    return new_collection_data

@router.get("/", response_model=List[CollectionResponse])
async def get_user_collections():
    # user = Depends(get_current_active_user)
    # user_id = user.id
    user_id = "user123" # Mock user_id
    # This should fetch collections where user_id matches OR user is a member of collection.team_id
    # For simplicity, returning all for now
    user_cols = [col for col in MOCK_DB_COLLECTIONS.values() if col["user_id"] == user_id or (col["team_id"] and True)] # True is placeholder for team membership check
    return user_cols

@router.get("/{collection_id}", response_model=CollectionResponse)
async def get_collection(collection_id: str):
    # user = Depends(get_current_active_user)
    # user_id = user.id
    if collection_id not in MOCK_DB_COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    collection_data = MOCK_DB_COLLECTIONS[collection_id]
    # Add permission check: user_id must match or user must be part of team_id
    return collection_data

@router.put("/{collection_id}", response_model=CollectionResponse)
async def update_collection(collection_id: str, collection_update: CollectionUpdate):
    # user = Depends(get_current_active_user)
    # user_id = user.id
    if collection_id not in MOCK_DB_COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    # Add permission check here
    stored_collection_data = MOCK_DB_COLLECTIONS[collection_id]
    update_data = collection_update.model_dump(exclude_unset=True)
    updated_collection = stored_collection_data.copy()
    updated_collection.update(update_data)
    MOCK_DB_COLLECTIONS[collection_id] = updated_collection
    logger.info(f"Collection {collection_id} updated.")
    return updated_collection

@router.delete("/{collection_id}", status_code=204)
async def delete_collection(collection_id: str):
    # user = Depends(get_current_active_user)
    # user_id = user.id
    if collection_id not in MOCK_DB_COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    # Add permission check here
    del MOCK_DB_COLLECTIONS[collection_id]
    # Also remove entries from MOCK_DB_SWIPE_FILES_IN_COLLECTION
    keys_to_delete = [key for key in MOCK_DB_SWIPE_FILES_IN_COLLECTION if key[0] == collection_id]
    for key in keys_to_delete:
        del MOCK_DB_SWIPE_FILES_IN_COLLECTION[key]
    logger.info(f"Collection {collection_id} deleted.")
    return

@router.post("/{collection_id}/swipefiles", status_code=201)
async def add_swipe_file_to_collection(collection_id: str, request: AddSwipeFileToCollectionRequest):
    # user = Depends(get_current_active_user)
    if collection_id not in MOCK_DB_COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    # Add permission check for collection access
    # Check if swipe_file_id exists (mocked for now)
    swipe_file_id = request.swipe_file_id
    if (collection_id, swipe_file_id) in MOCK_DB_SWIPE_FILES_IN_COLLECTION:
        raise HTTPException(status_code=400, detail="Swipe file already in collection")
    
MOCK_DB_SWIPE_FILES_IN_COLLECTION[(collection_id, swipe_file_id)] = {"collection_id": collection_id, "swipe_file_id": swipe_file_id}
    logger.info(f"Swipe file {swipe_file_id} added to collection {collection_id}.")
    return {"message": "Swipe file added to collection successfully."}

@router.delete("/{collection_id}/swipefiles/{swipe_file_id}", status_code=204)
async def remove_swipe_file_from_collection(collection_id: str, swipe_file_id: str):
    # user = Depends(get_current_active_user)
    if collection_id not in MOCK_DB_COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    # Add permission check for collection access
    if (collection_id, swipe_file_id) not in MOCK_DB_SWIPE_FILES_IN_COLLECTION:
        raise HTTPException(status_code=404, detail="Swipe file not found in this collection")

    del MOCK_DB_SWIPE_FILES_IN_COLLECTION[(collection_id, swipe_file_id)]
    logger.info(f"Swipe file {swipe_file_id} removed from collection {collection_id}.")
    return

# Need to add endpoints for listing swipe files in a collection
# @router.get("/{collection_id}/swipefiles", response_model=List[SwipeFileResponse]) # Define SwipeFileResponse
# async def get_swipe_files_in_collection(collection_id: str):
#     pass

"""
